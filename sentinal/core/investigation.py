"""Evidence-based investigation projection over immutable source observations."""
from __future__ import annotations
import hashlib
import json
import re
from datetime import datetime, timezone
from .bounty_policy import classify_code_change, code_location, strongest_eligibility

PATTERNS = {
    "Permissions": r"\b(?:require|assert)\s*\([^\n]*(?:msg\.sender|owner|role|auth)|\b(?:onlyOwner|onlyRole|hasRole|require_auth|assert_owner)\b",
    "Recipient validation hooks": r"\b(?:_checkRecipient|_hasRecipientCheck)\s*\(|\b(?:require|assert)\s*\([^\n]*(?:recipient|receiver)",
    "External calls and money movement": r"\b(?:delegatecall|call|transfer|transferFrom|safeTransfer|safeTransferFrom|send|invoke|invoke_signed)\s*\(",
    "Accounting arithmetic": r"\b(?:balances?|shares?|totalSupply|totalAssets|debt|collateral|interest|reserve)\b[^;\n]*(?:[+*/-]=|\+\+|--|=\s*[^;\n]*[+*/-])",
    "Upgrade and initialization": r"\b(?:initialize|reinitialize|upgradeTo|upgradeToAndCall|_authorizeUpgrade|setImplementation)\s*\(",
}
_RUNTIME_SUFFIXES = {"sol","vy","rs","move","cairo","go","py","js","ts","tsx","jsx","c","cpp","h","hpp","java","kt"}
_NOISE_PARTS = {"docs","tests","test","fixtures","mocks","cltest","testutils","testdata"}


def analyze_diff(files):
    evidence, excluded = [], []
    for file in files:
        path = str(file.get("path") or file.get("filename") or "")
        suffix = path.rsplit(".",1)[-1].lower()
        filename = path.rsplit("/",1)[-1].lower()
        noise = bool(set(path.lower().split("/")) & _NOISE_PARTS or filename.endswith(("_test.go", ".test.ts", ".test.js", ".spec.ts", ".spec.js", "test.sol", "tests.sol")) or filename.startswith("test_"))
        for line in str(file.get("patch") or "").splitlines():
            if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
                continue
            raw = line[1:].strip()
            if not raw:
                continue
            reason = None
            if noise:
                reason = "Test or support code"
            elif suffix not in _RUNTIME_SUFFIXES:
                reason = "Non-runtime file"
            elif raw.startswith(("//", "/*", "*", "#")):
                reason = "Comment or preprocessor line"
            elif re.match(r"^(?:import|from|use|package)\b", raw) or re.fullmatch(r'(?:_\s+)?["\x27][^"\x27]+["\x27][,;]?', raw):
                reason = "Import or module declaration"
            if reason:
                if len(excluded) < 20:
                    excluded.append({"path":path,"line":line[:500],"reason":reason})
                continue
            # Match executable tokens, not keywords embedded inside string literals.
            code = re.sub(r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|`[^`]*`', '""', raw).split("//",1)[0]
            for label, pattern in PATTERNS.items():
                if re.search(pattern, code, re.I):
                    evidence.append({"area":label,"path":path,"line":line[:500],"strength":"behavior","basis":"Changed executable-token heuristic; manual review required"})
            structural = re.search(r"\b(?:struct|enum|interface)\s+\w+", code)
            visibility = suffix in {"sol","vy"} and re.search(r"\b(?:public|external|private|internal)\b",code)
            if structural or visibility:
                evidence.append({"area":"Type or interface declaration" if structural else "Visibility declaration","path":path,"line":line[:500],"strength":"structural","basis":"Declaration change; behavior and storage effects not established"})
    return evidence[:100], excluded


def significance(files):
    return analyze_diff(files)[0]


def assess(event, policy, lifecycle="active"):
    files = [{**file, "repo": file.get("repo") or event.get("metadata", {}).get("repository"), "path": file.get("path") or file.get("filename")} for file in (event.get("metadata") or {}).get("changed_files") or []]
    assets = [{**row, "location": code_location(row.get("url"))} for row in policy.get("scope", []) if isinstance(row, dict)]
    classifications, scope_evidence, scoped_paths = [], [], set()
    for file in files:
        eligibility, rows = classify_code_change(file, assets, policy.get("primacy_rule"))
        if eligibility == "confirmed_scoped":
            scoped_paths.add(file["path"])
        classifications.append(eligibility)
        scope_evidence.extend(rows)
    scope = strongest_eligibility(classifications) if classifications else "unresolved_mapping"
    semantic, excluded = analyze_diff(files)
    for row in semantic:
        row["scope_confirmed"] = row["path"] in scoped_paths
    actionable = any(row["scope_confirmed"] and row.get("strength") == "behavior" for row in semantic)
    deployment = "Unverified"
    if event.get("source_tags") and "implementation_upgrade" in event["source_tags"]:
        address = str(event.get("entity") or "").lower()
        chain_id = event.get("metadata", {}).get("chain_id")
        scoped = bool(re.fullmatch(r"0x[0-9a-f]{40}", address)) and chain_id is not None and any(address in str(asset.get("url") or asset.get("address") or "").lower() and str(asset.get("chain_id")) == str(chain_id) for asset in assets)
        actionable = scoped
        scope = "confirmed_scoped" if scoped else "unresolved_mapping"
        if scoped:
            scope_evidence.append({"asset": address, "match": "scoped_address", "reason": "Observed proxy address occurs in published scope"})
        semantic = [{"area": "Implementation changed", "path": address, "line": f'{event.get("before")} -> {event.get("after")}', "strength": "behavior", "scope_confirmed": scoped, "basis": "Recorded on-chain storage observation"}]
        deployment = "On-chain implementation observation; source commit mapping unverified"
    incomplete = bool(event.get("metadata", {}).get("truncated") or event.get("metadata", {}).get("history_rewritten") or any(file.get("patch_truncated") for file in files))
    category = "lead" if semantic and actionable and lifecycle == "active" else "signal"
    reason = "Security-relevant changed lines with a current scope mapping" if category == "lead" else ("Program is not active" if lifecycle != "active" else "Security-relevant files need a current scope mapping" if any(row.get("strength") == "behavior" for row in semantic) else "Declaration changes only; security behavior not established" if semantic else "Activity only; no security-relevant changed-line evidence")
    now = datetime.now(timezone.utc)
    try:
        stamp = datetime.fromisoformat(event["detected_at"])
        age = max(0, (now - stamp).total_seconds() / 86400)
    except (ValueError, TypeError, KeyError):
        age = None
    priority = min(100, (35 if semantic else 5) + (20 if scope == "confirmed_scoped" else 0) + (15 if deployment != "Unverified" else 0) + (10 if age is not None and age < 7 else 0))
    if incomplete:
        priority = max(0, priority - 20)
    return {"category": category, "why": reason, "priority": priority, "scope": scope or "unresolved_mapping", "scope_evidence": scope_evidence, "deployment": deployment, "significance": semantic, "event_id": event.get("id"), "excluded_matches": excluded, "diff_confidence": "Incomplete" if incomplete else "Changed snippets observed" if any(f.get("patch") for f in files) else "No diff snippets", "freshness_days": round(age, 1) if age is not None else None}


def investigation_key(program_id, component):
    return hashlib.sha256(f"{program_id}|{component}".encode()).hexdigest()[:24]


def signature(events):
    content = []
    for event in events:
        for file in event.get("metadata", {}).get("changed_files", []):
            patch = file.get("patch")
            lines = [line for line in str(patch or "").splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
            content.append((file.get("path") or file.get("filename"), file.get("status"), lines if patch else (file.get("additions"), file.get("deletions"), event.get("after"))))
        if "implementation_upgrade" in event.get("source_tags", []):
            content.append((event.get("entity"),event.get("after")))
    return hashlib.sha256(json.dumps(sorted(content,key=str),sort_keys=True).encode()).hexdigest()


def investigations(dossier, reviews):
    policy, lifecycle = dossier["policy"], dossier["lifecycle"]
    buckets, signals = {}, []
    for event in dossier["changes"]:
        if event.get("source_tags") and any(tag in event["source_tags"] for tag in ("repository_activity", "release_boundary", "production_diff", "implementation_upgrade")):
            component = event["metadata"].get("repository") or event["entity"]
            buckets.setdefault(component, []).append(event)
        else:
            signals.append(event)
    rows = []
    for component, history in buckets.items():
        key = investigation_key(dossier["id"], component)
        checkpoint = reviews.get(key) or {}
        boundary = int(checkpoint.get("reviewed_through_id") or 0)
        relevant_signals = []
        for signal in signals:
            tags = set(signal.get("source_tags") or [])
            if tags & {"scope"}:
                # Link scope signals only to the repository they actually name.
                if component.lower() not in json.dumps([signal.get("before"),signal.get("after"),signal.get("metadata")]).lower():
                    continue
            if tags & {"scope", "impact", "policy", "program_lifecycle", "reward_ceiling", "reward_tier", "fee"}:
                relevant_signals.append(signal)
        context = hashlib.sha256(json.dumps({"scope": [row for row in policy.get("scope", []) if component.lower() in json.dumps(row).lower()], "rules": policy.get("policy"), "impacts": policy.get("impacts"), "lifecycle": lifecycle},sort_keys=True).encode()).hexdigest()
        context_changed = bool(checkpoint) and checkpoint.get("context_signature") != context
        deployment_links = [row for row in dossier.get("deployments", []) if row.get("repository") == component and row.get("commit") == history[0].get("after")]
        for signal in dossier["changes"]:
            if "implementation_upgrade" not in signal.get("source_tags", []):
                continue
            if any(str(row.get("address") or row.get("proxy") or "").lower() == str(signal["entity"]).lower() and row.get("implementation") == signal.get("after") and str(row.get("chain_id")) == str(signal.get("metadata", {}).get("chain_id")) and row.get("chain_id") is not None for row in deployment_links):
                relevant_signals.append(signal)
        context = hashlib.sha256((context + json.dumps(deployment_links,sort_keys=True)).encode()).hexdigest()
        context_changed = bool(checkpoint) and checkpoint.get("context_signature") != context
        pending = [event for event in history if event["id"] > boundary and event["status"] not in ("dismissed", "resolved")]
        if context_changed and not pending:
            pending = [history[0]]
        assessments = [assess(event, policy, lifecycle) for event in pending]
        current_signature = signature(pending)
        suppressed = bool(pending and checkpoint.get("status") == "dismissed" and not context_changed and all(signature([event]) in checkpoint.get("suppressed_signatures", []) for event in pending))
        if suppressed:
            pending, assessments = [], []
        status = checkpoint.get("status") if pending and checkpoint.get("status") in ("watching", "auditing") else "open" if pending else checkpoint.get("status", "reviewed")
        category = "lead" if any(a["category"] == "lead" for a in assessments) else "signal"
        rows.append({"id": key, "component": component, "category": category, "status": status, "active": lifecycle == "active" and bool(pending), "reopened": bool(checkpoint.get("status") in ("reviewed", "dismissed") and pending), "reopen_reason": "Program scope, rules or opportunity changed" if context_changed else "New code evidence or activity requiring reassessment" if checkpoint and pending else None, "event_ids": [event["id"] for event in pending], "history_ids": [event["id"] for event in history], "change_count": len(pending), "baseline_commit": checkpoint.get("baseline_commit") or history[-1].get("before"), "observed_head": history[0].get("after"), "reviewed_through_id": boundary, "assessments": assessments, "priority": max((a["priority"] for a in assessments), default=0), "deployment_links": deployment_links, "signals": [{"id":e["id"],"kind":e["kind"],"detected_at":e["detected_at"]} for e in relevant_signals], "checkpoint": checkpoint, "content_signature": current_signature, "context_signature": context, "why": assessments[0]["why"] if assessments else "No unreviewed changes", "suppressed_equivalent": suppressed})
    from .explanations import explain
    for row in rows:
        row["explanation"] = explain(row, dossier, history_by_id={event["id"]: event for event in dossier["changes"]})
    return sorted(rows, key=lambda row:(row["active"],row["category"] == "lead",row["priority"]),reverse=True)
