"""Deterministic plain-language explanations grounded in recorded evidence."""
from datetime import datetime, timezone

AREAS = {
    "Permissions": ("authorization checks", "which callers are allowed to perform the changed operations"),
    "Recipient validation hooks": ("recipient-validation hooks", "how recipients are validated before payments"),
    "External calls and money movement": ("external calls or token transfers", "where funds move and whether validation happens before external calls"),
    "Accounting arithmetic": ("balance or share arithmetic", "rounding, balance conservation and accounting invariants"),
    "Upgrade and initialization": ("upgrade or initialization operations", "who can initialize or replace implementations"),
    "Implementation changed": ("an observed implementation replacement", "the new implementation and its chain-specific scope"),
}


def explain(investigation, dossier, history_by_id):
    assessments = investigation["assessments"]
    strong, weak, excluded, references = [], [], [], []
    for assessment in assessments:
        for row in assessment["significance"]:
            (strong if row.get("strength") == "behavior" else weak).append(row)
            references.append({"event_id":assessment.get("event_id"),**row})
        excluded.extend({"event_id":assessment.get("event_id"),**row} for row in assessment.get("excluded_matches", []))
    if investigation["category"] == "lead":
        strong = [row for row in strong if row.get("scope_confirmed")]
    areas = list(dict.fromkeys(row["area"] for row in strong))
    paths = list(dict.fromkeys(row["path"] for row in strong + weak))
    described = [AREAS.get(area,(area.lower(),"the changed behavior"))[0] for area in areas]
    limitations = ["This is a review hypothesis, not a confirmed vulnerability or payout assessment."]
    if not any(a["deployment"].startswith("On-chain") for a in assessments):
        limitations.append("The changed repository commits have not been matched to a deployed implementation.")
    if any(a["diff_confidence"] == "Incomplete" for a in assessments):
        limitations.append("The comparison is incomplete; omitted changes may alter the interpretation.")
    if any(a["diff_confidence"] == "No diff snippets" for a in assessments):
        limitations.append("Some accumulated observations have no diff snippets and cannot support behavioral claims.")
    if not investigation["change_count"]:
        label = "Closed investigation"
        trigger = "No unreviewed observations remain in this investigation."
        meaning = "Its previous evidence and review checkpoint are retained in the history."
        next_step = "Revisit it when new code or relevant program context changes."
    elif dossier["lifecycle"] != "active":
        label = "Program inactive"
        trigger = "Changes are recorded, but the program is currently " + dossier["lifecycle"] + "."
        meaning = "The investigation is retained outside the active shortlist."
        next_step = "Confirm program availability and rules before starting an investigation."
    elif investigation["category"] == "lead":
        label = "Concrete review target"
        trigger = "Changed lines include " + ", ".join(described) + (" in " + ", ".join(paths[:3]) if paths else "") + "."
        meaning = "At least one behavior-related match is in currently scoped code. This provides a concrete reason to inspect the affected execution paths; exploitability is not established."
        next_step = "Trace " + "; ".join(dict.fromkeys(AREAS.get(area,(area,"the changed behavior"))[1] for area in areas)) + ". Then confirm the eligible impact and deployed version."
    elif strong:
        label = "Scope needs confirmation"
        trigger = "Changed lines include " + ", ".join(described) + "."
        meaning = "The relevant code does not yet have a confirmed current scope mapping. Keep this as an activity signal until eligibility is resolved."
        next_step = "Map these exact files or deployment addresses to the current program scope before deeper investigation."
    elif weak:
        label = "Weak evidence"
        trigger = "The available matches are type, interface or visibility declarations" + (" in " + ", ".join(paths[:3]) if paths else "") + "."
        meaning = "Declarations alone do not show an authorization change, fund-accounting operation or deployed-contract storage change. The evidence supports an activity signal, not an actionable lead."
        next_step = "Inspect the surrounding implementation and callers for an actual behavioral change."
    elif excluded:
        label = "Likely detector noise"
        reasons = list(dict.fromkeys(row["reason"].lower() for row in excluded))
        trigger = "Observed snippets include " + ", ".join(reasons) + "."
        meaning = "Those snippets are excluded from promotion. No qualifying runtime security behavior was established from the remaining available lines."
        next_step = "Check whether the comparison contains separate runtime changes; otherwise this activity can be dismissed."
    else:
        label = "Insufficient evidence"
        trigger = "Repository or deployment activity was observed without qualifying behavioral evidence."
        meaning = "The available data does not justify promoting this activity into a lead."
        next_step = "Inspect the source comparison and establish the relevant behavior and scope."
    if investigation["change_count"] and any(a["diff_confidence"] == "Incomplete" for a in assessments):
        meaning += " The comparison is incomplete."
    if investigation["category"] == "lead" and not any(a["deployment"].startswith("On-chain") for a in assessments):
        meaning += " Deployment relevance remains unverified."
    event_ids = investigation["event_ids"]
    return {"assessment":label,"what_triggered":trigger,"what_it_means":meaning,"limitations":limitations,"next_inspection":next_step,"evidence":references[:12],"excluded_evidence":excluded[:6],"method":"Deterministic evidence rules; no model-generated claims", "assessed_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"latest_observation":max((history_by_id[eid]["detected_at"] for eid in event_ids if eid in history_by_id),default=None),"policy_observed_at":dossier.get("policy_observed_at")}
