"""Evidence-backed program selection and portable investigation dossiers."""
from __future__ import annotations
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse, quote, unquote
from .core.investigation import investigations, signature
from .onchain import program_view

DEFAULT_PROFILE = {"chains": ["EVM"], "languages": ["Solidity"], "protocol_types": []}
LANGUAGES = {"sol": "Solidity", "vy": "Vyper", "rs": "Rust", "move": "Move", "cairo": "Cairo", "go": "Go", "ts": "TypeScript", "js": "JavaScript"}


def safe_url(value):
    if not isinstance(value, str):
        return None
    parsed = urlparse(value)
    return value if parsed.scheme in ("https", "http") and parsed.hostname and not parsed.username and not parsed.password else None


def validate_evidence(value):
    if not isinstance(value, dict):
        raise ValueError("Research evidence must be an object")
    allowed = {"chains", "languages", "protocol_types", "dependencies", "complexity", "setup", "audits", "known_issues", "findings", "deployments", "funds", "payout_conditions"}
    if set(value) - allowed:
        raise ValueError("Unknown research evidence field")
    if len(json.dumps(value)) > 50000:
        raise ValueError("Research evidence is too large")
    for key in ("chains", "languages", "protocol_types", "dependencies"):
        if key in value and (not isinstance(value[key], list) or any(not isinstance(x, str) or len(x) > 200 for x in value[key])):
            raise ValueError(f"{key} must be a list of short strings")
    for key in ("complexity", "setup", "payout_conditions"):
        if key in value and (not isinstance(value[key], str) or len(value[key]) > 10000):
            raise ValueError(f"{key} must be text")
    for key in ("audits", "known_issues", "findings", "deployments"):
        if key in value:
            if not isinstance(value[key], list) or len(value[key]) > 100:
                raise ValueError(f"{key} must be a list of evidence records")
            for row in value[key]:
                if not isinstance(row, dict) or not safe_url(row.get("url")):
                    raise ValueError(f"Each {key} record needs a public http(s) evidence URL")
                for field, item in row.items():
                    if not isinstance(item, (str, int, float, bool, type(None))) or len(str(item)) > 2000:
                        raise ValueError("Evidence records must contain short scalar fields")
                if row.get("date"):
                    datetime.fromisoformat(row["date"])
                if key == "deployments":
                    address = str(row.get("address", ""))
                    if not address or not row.get("chain"):
                        raise ValueError("Deployment needs a chain and address")
                    if address.startswith("0x") and not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                        raise ValueError("EVM deployment address must be a 20-byte address")
    if "funds" in value and value["funds"] is not None:
        row = value["funds"]
        if not isinstance(row, dict) or not safe_url(row.get("url")) or not row.get("observed_at"):
            raise ValueError("Funds need an evidence URL and observation date")
        datetime.fromisoformat(row["observed_at"])
        if not isinstance(row.get("amount"), (int, float)) or isinstance(row["amount"], bool) or not 0 <= row["amount"] < 1e15:
            raise ValueError("Funds amount must be a nonnegative number")
    return value


def profile(store, value=None):
    if value is not None:
        if not isinstance(value, dict) or set(value) != set(DEFAULT_PROFILE):
            raise ValueError("Profile requires chains, languages and protocol_types")
        validate_evidence(value)
        store.set_runtime_status("hunter_profile", value)
    return store.get_runtime_status("hunter_profile") or DEFAULT_PROFILE


def _events(store, protocol_ids=None):
    """Read only event histories relevant to the requested dossiers."""
    ids = tuple(dict.fromkeys(protocol_ids)) if protocol_ids is not None else None
    if ids is not None and not ids:
        return {}
    where = "category != 'baseline'"
    if ids is not None:
        where += " AND protocol_id IN (" + ",".join("?" for _ in ids) + ")"
    with store.connect() as db:
        rows = db.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY detected_at DESC, id DESC",
            ids or (),
        ).fetchall()
    result = {}
    for row in rows:
        event = dict(row)
        for name in ("before", "after", "metadata", "evidence", "reasons"):
            event[name] = json.loads(event.pop(name + "_json") or "null")
        result.setdefault(event["protocol_id"], []).append(event)
    return result


def change_type(event, kind_specs=None):
    if kind_specs is None:
        from .core.registry import default_registry
        kind_specs = default_registry().kind_specs()
    spec = kind_specs.get(event.get("kind"))
    tags = set(event.get("source_tags") or (spec.tags if spec else ()))
    return "code" if tags & {"repository_activity", "release_boundary", "production_diff", "implementation_upgrade"} else "program"


def dossiers(store, program_id=None):
    programs = store.list_programs(with_targets=True)
    program_counts = Counter(p['protocol_id'] for p in programs)
    platform_counts = Counter((p['protocol_id'], p['platform']) for p in programs)
    if program_id is not None:
        programs = [p for p in programs if p["id"] == program_id]
        if not programs:
            return []
    grouped = _events(store, tuple(p['protocol_id'] for p in programs) if program_id is not None else None)
    specs = store.adapters.kind_specs()
    for events in grouped.values():
        for event in events:
            event["source_tags"] = list(specs[event["kind"]].tags) if event["kind"] in specs else []
            event["change_type"] = change_type(event, specs)
    saved = {key: row.get("value") for key, row in store.runtime_status().items()}
    hunter = profile(store)
    with store.connect() as db:
        if program_id is not None:
            # Shared repository targets can belong to a different protocol's
            # stored source row. Include the selected program's target keys too.
            target_keys = tuple(dict.fromkeys(
                f'{target["source_type"]}:{target["target_key"]}'
                for target in programs[0]['targets']
            ))
            where = 'protocol_id = ?'
            params = (programs[0]['protocol_id'],)
            if target_keys:
                where += ' OR source_key IN (' + ','.join('?' for _ in target_keys) + ')'
                params += target_keys
            states = [dict(row) for row in db.execute(
                f'SELECT * FROM source_state WHERE {where}', params,
            )]
        else:
            states = [dict(row) for row in db.execute('SELECT * FROM source_state')]
    by_key = {row["source_key"]: row for row in states}
    policy_types = set(store.policy_source_types())
    # Batch the per-program store lookups; per-program connections dominate the
    # cost of a whole-dashboard rebuild.
    rules = store.get_primacy_rules(program["id"] for program in programs)
    reviews = store.investigation_reviews_by_program(program["id"] for program in programs)
    result = []
    for program in programs:
        pid = program["id"]
        facts = saved.get(f"research:{pid}") or {}
        events = [e for e in grouped.get(program["protocol_id"], []) if (not e["metadata"].get("platform") or e["metadata"]["platform"] == program["platform"]) and e["metadata"].get("program_id", e["metadata"].get("manual_program_id", pid)) == pid]
        if program_counts[program['protocol_id']] > 1:
            events = [e for e in events if e['metadata'].get('program_id') is not None or e['metadata'].get('manual_program_id') is not None
                      or (e['metadata'].get('platform') and platform_counts[(program['protocol_id'],program['platform'])]==1)]
        policy_states = [row for row in states if row['program_id'] == pid and row["source_type"] in policy_types]
        policy_state = max(policy_states, key=lambda row: row["updated_at"], default={})
        policy = json.loads(policy_state.get("payload_json") or "{}")
        if policy.get("max_bounty") is None:
            policy["max_bounty"] = program.get("max_bounty")
        repositories, deployments = [], []
        for target in program["targets"]:
            if not target["active"]:
                continue
            config = target["config"]
            state = by_key.get(f'{target["source_type"]}:{target["target_key"]}', {})
            payload = json.loads(state.get("payload_json") or "{}")
            repo = config.get("repository")
            if repo and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
                head = payload.get("head")
                pinned = head if isinstance(head, str) and re.fullmatch(r"[0-9a-fA-F]{40}", head) else None
                repositories.append({"repository": repo, "commit": pinned, "url": f"https://github.com/{repo}" + (f"/tree/{pinned}" if pinned else ""), "observed_at": state.get("updated_at"), "audit_repository_candidate": bool(re.search(r"audit|security.report", repo, re.I))})
            if payload.get("proxy"):
                deployments.append({**payload, "observed_at": state.get("updated_at"), "evidence_type": "RPC storage observation", "source_commit_match": "unverified"})
        policy["primacy_rule"] = rules.get(pid)
        files = [file for event in events for file in (event["metadata"].get("changed_files") or [])]
        languages = sorted({LANGUAGES[path.rsplit(".", 1)[-1]] for file in files if (path := file.get("path") or file.get("filename") or "").rsplit(".", 1)[-1] in LANGUAGES})
        scoped_text = json.dumps(policy.get("scope") or [])
        languages = sorted(set(languages) | {name for suffix, name in LANGUAGES.items() if re.search(r"\." + re.escape(suffix) + r"(?:[\"?/#\s]|$)", scoped_text)})
        inferred_chains = ["EVM"] if "Solidity" in languages or "Vyper" in languages or deployments else []
        chain_hosts = {"etherscan.io": "Ethereum", "arbiscan.io": "Arbitrum", "optimistic.etherscan.io": "Optimism", "basescan.org": "Base", "polygonscan.com": "Polygon", "bscscan.com": "BNB Chain", "snowtrace.io": "Avalanche", "solscan.io": "Solana", "suivision.xyz": "Sui", "explorer.aptoslabs.com": "Aptos"}
        scope_urls = [row.get("url", "") for row in policy.get("scope", []) if isinstance(row, dict)]
        inferred_chains += [chain for host, chain in chain_hosts.items() if any(urlparse(url).hostname == host for url in scope_urls)]
        type_text = (program["name"] + " " + " ".join(repo["repository"] for repo in repositories)).lower()
        inferred_types = [label for label, pattern in {"Lending": r"lend|aave|compound|borrow", "DEX": r"swap|uniswap|dex|curve", "Bridge": r"bridge|cross.chain|layerzero", "Oracle": r"oracle|chainlink|pyth", "Staking": r"staking|stake|lido", "Vault": r"vault|yearn"}.items() if re.search(pattern, type_text)]
        fit = {"chains": facts.get("chains") or sorted(set(inferred_chains)), "languages": facts.get("languages") or languages, "protocol_types": facts.get("protocol_types") or inferred_types}
        matches = {key: sorted(set(map(str.lower, fit[key])) & set(map(str.lower, hunter[key]))) for key in fit}
        open_events = [e for e in events if e["status"] in ("new", "watching", "auditing")]
        scope_changes = [e for e in open_events if e["category"] == "lead" and e["eligibility"] == "confirmed_scoped"]
        audit_gaps = []
        for audit in facts.get("audits", []):
            candidates = [e for e in events if audit.get("date") and e["detected_at"][:10] > audit["date"][:10] and (not audit.get("repository") or audit["repository"] in e["entity"])]
            audit_gaps.append({"audit": audit, "baseline_diffs": [{"repository": repo["repository"], "url": f'https://github.com/{repo["repository"]}/compare/{audit["commit"]}...{repo["commit"]}'} for repo in repositories if audit.get("repository") == repo["repository"] and re.fullmatch(r"[0-9a-fA-F]{40}", str(audit.get("commit", ""))) and repo["commit"]], "candidates": [{"id": e["id"], "entity": e["entity"], "diff_url": safe_url(e["metadata"].get("compare_url")), "focus": _focus(e)} for e in candidates], "confidence": "Detection date only; commit ancestry and audit coverage unverified"})
        missing = []
        for name, known in (("Deployment-to-commit mapping", any(d.get("commit") for d in facts.get("deployments", []))), ("Audit coverage", facts.get("audits")), ("Available reward funds", facts.get("funds")), ("Dependencies", facts.get("dependencies")), ("Protocol type", fit["protocol_types"])):
            if not known:
                missing.append(name)
        for event in events:
            event["focus"] = _focus(event)
            for file in event["metadata"].get("changed_files", []):
                repo = file.get("repo") or event["metadata"].get("repository")
                head = event.get("after")
                path = file.get("path") or file.get("filename")
                if isinstance(head, str) and re.fullmatch(r"[0-9a-fA-F]{40}", head) and isinstance(repo, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) and path:
                    file["pinned_source_url"] = f"https://github.com/{repo}/blob/{head}/{quote(path, safe='/')}"
        result.append({"id": pid, "name": program["name"], "protocol_id": program["protocol_id"], "platform": program["platform"], "lifecycle": program["lifecycle"], "url": program.get("url"), "policy": policy, "policy_observed_at": policy_state.get("updated_at"), "change_count": len(events), "open_change_count": len(open_events), "scoped_change_count": len(scope_changes), "latest_change": events[0]["detected_at"] if events else None, "priority": max((e["score"] for e in open_events), default=0), "fit": fit, "fit_matches": matches, "fit_basis": "Recorded tags or heuristics from scope URLs, file extensions and repository names; inferred labels need review", "complexity": facts.get("complexity") or f"{len(set(f.get('path') or f.get('filename') for f in files))} distinct changed files across {len(repositories)} monitored repositories; total complexity unassessed", "dependencies": facts.get("dependencies") or [], "public_history": {key: facts.get(key) or [] for key in ("audits", "known_issues", "findings")}, "audit_gaps": audit_gaps, "repositories": repositories, "deployments": deployments + [{**d, "evidence_type": "Manually recorded; verify linked evidence"} for d in facts.get("deployments", [])], "funds": facts.get("funds"), "payout_conditions": facts.get("payout_conditions") or policy.get("policy") or {}, "setup": facts.get("setup") or "Inspect the pinned repository README and dependency manifests. Run target code only in an isolated environment; no project setup has been executed by Sentinal.", "unknowns": missing, "changes": events, "evidence": facts, "evidence_observed_at": saved.get(f"research_updated:{pid}")})
    for row in result:
        program = next(program for program in programs if program['id'] == row['id'])
        status = saved.get(f'onchain:{row["id"]}')
        checker = getattr(store, 'onchain_status', None)
        if callable(checker):
            status = checker(row['id'], status)
        row['onchain'] = program_view(program, row['policy'], row['changes'], status)
        row["code_changes"] = [event for event in row["changes"] if change_type(event, specs) == "code"]
        row["program_changes"] = [event for event in row["changes"] if change_type(event, specs) == "program"]
        row["code_change_count"] = len(row["code_changes"])
        row["program_change_count"] = len(row["program_changes"])
        row["investigations"] = investigations(row, reviews.get(row["id"]) or {})
        for item in row["investigations"]:
            if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(item["component"])) and all(isinstance(item.get(key),str) and re.fullmatch(r"[0-9a-fA-F]{40}",item[key]) for key in ("baseline_commit","observed_head")):
                item["review_diff_url"] = f'https://github.com/{item["component"]}/compare/{item["baseline_commit"]}...{item["observed_head"]}'
        active = [item for item in row["investigations"] if item["active"]]
        row["scoped_change_count"] = sum(a["scope"] == "confirmed_scoped" for item in row["investigations"] for a in item["assessments"])
        row["lead_count"] = sum(item["category"] == "lead" for item in active)
        row["activity_count"] = sum(item["category"] == "signal" for item in active)
        row["unreviewed_investigation_count"] = len(active)
        row["program_signals"] = [event for event in row["changes"] if not set(event["source_tags"]) & {"repository_activity", "release_boundary", "production_diff", "implementation_upgrade"}]
        row["raw_open_change_count"] = row["open_change_count"]
        row["open_change_count"] = len({event_id for item in active for event_id in item["event_ids"]}) + sum(event["status"] in ("new", "watching", "auditing") for event in row["program_signals"])
        row["signal_count"] = row["activity_count"] + sum(event["status"] in ("new", "watching", "auditing") for event in row["program_signals"])
        row["priority"] = max((item["priority"] for item in active), default=0)
    return sorted(result, key=lambda d: (d["lifecycle"] == "active", d["latest_change"] or ""), reverse=True)


def _focus(event):
    paths = " ".join(f.get("path") or f.get("filename") or "" for f in event["metadata"].get("changed_files", [])).lower()
    terms = {"Money movement": r"transfer|withdraw|deposit|swap|bridge", "Permissions": r"auth|owner|access|role|admin", "Accounting": r"vault|share|balance|interest|account|reward"}
    return [label + " (path heuristic)" for label, pattern in terms.items() if re.search(pattern, paths)] or ["Manual diff review required"]


def save_evidence(store, program_id, value):
    if store.get_program(program_id) is None:
        raise KeyError("Program not found")
    store.set_runtime_status(f"research:{program_id}", validate_evidence(value))
    store.set_runtime_status(f"research_updated:{program_id}", datetime.now(timezone.utc).isoformat())


def _export_label(value, fallback, length=100):
    label = re.sub(r"[^A-Za-z0-9_.-]", "-", str(value or ""))[:length].strip("._-")
    reserved = {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}
    if label.split(".")[0].upper() in reserved:
        label = ("repository-" + label)[:length].strip("._-")
    return label or fallback


def _export_revision(value):
    if isinstance(value, dict):
        value = value.get("head_sha") or value.get("sha") or value.get("tag_name") or value.get("target_commitish")
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
        return value[:10]
    return _export_label(value, "unknown")[:40]


def _export_folder(event, repository, compare_url):
    try:
        observed = datetime.fromisoformat(event.get("detected_at") or "")
        stamp = observed.replace(tzinfo=observed.tzinfo or timezone.utc).astimezone(timezone.utc).strftime("%Y-%m-%d_%H-%M-%SZ")
    except (TypeError, ValueError):
        stamp = "undated"
    before, after = event.get("before"), event.get("after")
    comparison = unquote(urlparse(compare_url or "").path).partition("/compare/")[2].split("...")
    if len(comparison) == 2 and all(comparison):
        before, after = comparison
    repo = _export_label(str(repository or "").replace("/", "--"), "repository", 60)
    return f"changes/{repo}/{stamp}_{_export_revision(before)}...{_export_revision(after)}"


def remove_patch_bodies(event):
    """Drop large patch text from a newly loaded event before sending dashboard JSON.

    Keep a marker so the UI can display a lazy patch control and download
    links without downloading the patch body with every dossier refresh.
    Mutates only this request's independent, deserialized event dictionary.
    """
    for file in (event.get('metadata') or {}).get('changed_files') or []:
        if not isinstance(file, dict):
            continue
        patch = file.pop('patch', None)
        if isinstance(patch, str) and patch.strip():
            file['patch_recorded'] = True
    return event


def write_package(dossier, output_file, kind_specs=None):
    """Write the original portable ZIP format to a seekable binary destination.

    Destination can be a SpooledTemporaryFile, allowing large ZIPs to spill to
    disk while keeping export memory bounded independently of archive size.
    """
    manifest = {"program": dossier["name"], "format": "recorded-file-diffs-v2", "changes": []}
    count = 0
    folders = set()
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
        for event in dossier["changes"]:
            if change_type(event, kind_specs) != "code":
                continue
            meta = event.get("metadata") or {}
            record = {"event_id": event["id"], "kind": event.get("kind"), "repository": meta.get("repository") or event.get("entity"),
                      "before": event.get("before"), "after": event.get("after"),
                      "observed_at": event.get("detected_at"), "compare_url": safe_url(meta.get("compare_url")),
                      "comparison_incomplete": bool(meta.get("truncated") or meta.get("history_rewritten")), "files": []}
            record['patch_coverage_unverified'] = bool(meta.get('patch_coverage_unverified'))
            record['patch_range_unavailable'] = bool(meta.get('patch_range_unavailable'))
            if meta.get('patch_unavailable_reason'):
                record['patch_unavailable_reason'] = meta['patch_unavailable_reason']
            folder = _export_folder(event, record["repository"], record["compare_url"])
            unique_folder = folder
            suffix = 2
            while unique_folder in folders:
                unique_folder = f"{folder}_{suffix}"
                suffix += 1
            folders.add(unique_folder)
            record["folder"] = unique_folder
            for index, file in enumerate(meta.get("changed_files") or [], 1):
                path = str(file.get("path") or file.get("filename") or "unknown")
                previous = str(file.get("previous_path") or file.get("previous_filename") or path)
                patch = file.get("patch")
                entry = {"path": path, "previous_path": previous, "status": file.get("status"),
                         "patch_status": "missing", "diff_file": None,
                         "patch_scope": file.get('patch_scope', 'comparison'),
                         "before": file.get('patch_before', event.get('before')),
                         "after": file.get('patch_after', event.get('after')),
                         **({'patch_unavailable_reason': file['patch_unavailable_reason']} if file.get('patch_unavailable_reason') else {})}
                valid_paths = all(not name.startswith(("/", "\\")) and "\\" not in name
                                  and ":" not in name and not any(part in ("", ".", "..") for part in name.split("/"))
                                  for name in (path, previous))
                if not valid_paths:
                    entry["patch_status"] = "invalid_path"
                elif isinstance(patch, str) and patch.strip():
                    name = re.sub(r"[^A-Za-z0-9_.-]", "_", path.replace("\\", "/").rsplit("/", 1)[-1])[:60] or "file"
                    partial = bool(file.get("patch_truncated"))
                    unverified = file.get('patch_scope') == 'legacy_unverified'
                    entry_path = f'{unique_folder}/{index:04d}-{name}{".unverified" if unverified else ".partial" if partial else ""}.diff'
                    old = '/dev/null' if file.get("status") == "added" else json.dumps('a/' + previous, ensure_ascii=False)
                    new = '/dev/null' if file.get("status") == "removed" else json.dumps('b/' + path, ensure_ascii=False)
                    headers = f'diff --git {json.dumps("a/" + previous, ensure_ascii=False)} {json.dumps("b/" + path, ensure_ascii=False)}\n'
                    if file.get("status") == "renamed":
                        headers += f'rename from {json.dumps(previous, ensure_ascii=False)}\nrename to {json.dumps(path, ensure_ascii=False)}\n'
                    with archive.open(entry_path, 'w') as patch_output:
                        patch_output.write((headers + f'--- {old}\n+++ {new}\n').encode('utf-8', 'backslashreplace'))
                        # Avoid another full-sized patch string just for a ZIP entry.
                        for offset in range(0, len(patch), 65536):
                            patch_output.write(patch[offset:offset + 65536].encode('utf-8', 'backslashreplace'))
                        if not patch.endswith('\n'):
                            patch_output.write(b'\n')
                    entry.update(patch_status='unverified' if unverified else "partial" if partial else "recorded", diff_file=entry_path)
                    count += 1
                record["files"].append(entry)
            manifest["changes"].append(record)
        manifest["diff_file_count"] = count
        archive.writestr('manifest.json', json.dumps(manifest, indent=2))
        archive.writestr('README.md', (f'# {dossier["name"]} file diffs\n\n{count} recorded file diffs.\n\n'
            'Folders group changes by repository, observation date (UTC), and compared revisions.\n'
            'Example: changes/owner--repository/2026-10-08_21-30-00Z_abc1234567...def1234567/\n'
            'The internal change ID remains in manifest.json; repeated ranges get a numeric suffix to keep observations separate.\n'
            'manifest.json identifies repositories, before/after revisions, comparison URLs and missing or partial patches.\n'
            'These are individual observed changes, not an aggregate net diff across all observations.\n'
            'Fallback patches have patch_scope=commit and their own before/after revisions in manifest.json.\n'
            'Historical patches ending in .unverified.diff retain their original text, but revision coverage is unverified.\n'
            'Commit patches are separate changes in recorded order, not an aggregate base/head diff.\n'
            'Review comparison patches and commit patches separately; they are not one combined applicable patch.\n'
            'Missing patches (including binary files) and invalid paths have no .diff file. Files ending in .partial.diff are truncated.\n'
            'Comparison-level incompleteness is recorded separately. Use the comparison URL to check full coverage.\n').encode('ascii', 'backslashreplace'))


def package(dossier, kind_specs=None):
    """Backward-compatible bytes exporter for small programmatic consumers.

    HTTP routes use write_package directly with a spooled output file.
    """
    buffer = io.BytesIO()
    write_package(dossier, buffer, kind_specs)
    return buffer.getvalue()


def review_investigation(store, program_id, key, request):
    if not isinstance(request, dict) or request.get("status") not in ("watching", "auditing", "reviewed", "dismissed"):
        raise ValueError("Choose watching, auditing, reviewed or dismissed")
    reasons = ("out_of_scope", "already_reviewed", "irrelevant_component", "other")
    if request["status"] == "dismissed" and request.get("reason") not in reasons:
        raise ValueError("Choose a dismissal reason")
    note = request.get("note", "")
    if not isinstance(note, str) or len(note) > 20000:
        raise ValueError("Review note must be at most 20000 characters")
    rows = dossiers(store, program_id)
    if not rows:
        raise KeyError("Program not found")
    item = next((row for row in rows[0]["investigations"] if row["id"] == key), None)
    if item is None:
        raise KeyError("Investigation not found")
    observed = max(item["history_ids"], default=0)
    if request.get("observed_through_id") != observed or request.get("context_signature") != item["context_signature"]:
        raise ValueError("Investigation changed; refresh before reviewing")
    previous = item["checkpoint"]
    final = request["status"] in ("reviewed", "dismissed")
    state = {"status":request["status"], "reason":request.get("reason"), "note":note,
        "reviewed_through_id": observed if final else item["reviewed_through_id"],
        "baseline_commit": item["observed_head"] if final else item["baseline_commit"],
        "content_signature": item["content_signature"] if final else previous.get("content_signature"),
        "suppressed_signatures": sorted(set(previous.get("suppressed_signatures", [])) | {signature([event]) for event in rows[0]["changes"] if event["id"] in item["event_ids"]}) if request["status"] == "dismissed" else previous.get("suppressed_signatures", []),
        "context_signature": item["context_signature"],
        "reviewed_at": datetime.now(timezone.utc).isoformat() if final else previous.get("reviewed_at")}
    store.review_investigation(program_id, key, state)
    return state
