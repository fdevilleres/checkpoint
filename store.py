"""Tracks which CVE IDs have already been drafted, so repeated runs don't duplicate
Gmail drafts, plus the last-checked timestamp per feed for incremental NVD queries.
Also persists full match results (keyed by CVE ID) so the local dashboard API
(server.py) can serve gateway-scoped advisory data without re-fetching from NVD."""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "state.json")


def load(path: str = _DEFAULT_PATH) -> dict:
    if not os.path.exists(path):
        state = {}
    else:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
    state.setdefault("seen_cve_ids", [])
    state.setdefault("last_checked", {})
    state.setdefault("results", {})
    state.setdefault("known_gateways", {})
    return state


def save(state: dict, path: str = _DEFAULT_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def mark_seen(state: dict, cve_id: str) -> None:
    if cve_id not in state["seen_cve_ids"]:
        state["seen_cve_ids"].append(cve_id)


def is_seen(state: dict, cve_id: str) -> bool:
    return cve_id in state["seen_cve_ids"]


def set_last_checked(state: dict, feed: str) -> None:
    state["last_checked"][feed] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def get_last_checked(state: dict, feed: str) -> str | None:
    return state["last_checked"].get(feed)


def record_result(state: dict, result) -> None:
    """Persists everything the local dashboard API needs to render this advisory
    for a gateway, keyed by CVE ID. `result` is a matcher.MatchResult."""
    adv = result.advisory
    state["results"][adv.cve_id] = {
        "cve_id": adv.cve_id,
        "title": adv.title,
        "summary": adv.summary,
        "severity": adv.severity,
        "cvss": adv.cvss,
        "kev": adv.kev,
        "source_url": adv.source_url,
        "published": adv.published,
        "needs_review": result.needs_review,
        "resolved_not_applicable": result.resolved_not_applicable,
        "matched_gateway_uids": [gw.uid for gw in result.matched_gateways],
        "sk_url": result.sk_url,
        # {gateway uid: [installed_take, required_take]} -- only populated when a
        # Take-based path (matcher._match_via_cp_advisory / _match_via_sk) confirmed
        # a patch gap.
        "gateway_take_gap": {uid: list(pair) for uid, pair in result.gateway_take_gap.items()},
        # Gateways in matched_gateways with NO Take that fixes them (EOS version) --
        # needs an upgrade, not a hotfix install.
        "eos_gateway_uids": sorted(result.eos_gateway_uids),
        # {gateway uid: max_vulnerable_take} -- known Take threshold for this specific
        # gateway that couldn't be confirmed against its installed Take (hotfix check
        # off, or undeterminable). Still attributed to the gateway, just unconfirmed.
        # {gateway uid: required Take} -- the Take to install, for gateways whose
        # currently-installed Take couldn't be read.
        "gateway_required_take": dict(result.gateway_required_take),
        # {gateway uid: "sk" | "inferred"} -- "sk" means the required Take came from
        # the sk-article's Solution table and is the real fix Take; "inferred" means
        # only the vulnerability threshold was available, so it's a lower bound and
        # must not be shown as a definitive "install this Take".
        "gateway_take_source": dict(result.gateway_take_source),
        "cp_severity": adv.cp_severity,
        "sk_id": adv.sk_id,
    }


def results_for_gateway(state: dict, uid: str) -> list[dict]:
    return [r for r in state["results"].values() if uid in r["matched_gateway_uids"]]


def unassigned_results(state: dict) -> list[dict]:
    """Advisories flagged for manual review that couldn't be pinned to any specific
    gateway (e.g. CPE data scoped to a management-server product line, or no CPE
    data at all). Shown on every gateway's tab rather than nowhere."""
    return [r for r in state["results"].values()
            if r["needs_review"] and not r["matched_gateway_uids"]]


def resolved_results(state: dict) -> list[dict]:
    """Advisories that had real CPE version data and were confidently determined to
    not affect any current gateway — recorded for auditability rather than silently
    dropped, so "checked, doesn't apply" is visibly distinct from "never checked"."""
    return [r for r in state["results"].values() if r.get("resolved_not_applicable")]


def set_known_gateways(state: dict, gateways) -> None:
    """Records which gateway UIDs were actually polled this run, so the dashboard
    API can tell "polled and genuinely clean" (0 matches, uid present here) apart
    from "never heard of this uid" (0 matches, uid absent) -- both look identical
    as an empty matched list otherwise. Confirmed live: two real external testers
    on different, never-reported gateways got byte-for-byte identical responses,
    which reads as "you're clean" when the truth is "we've never checked you".

    Callers should only call this with a complete inventory (skip it if any
    configured management server was unreachable this run), same reasoning as
    the already-seen advisory refresh: a partial inventory must not shrink the
    known set and make a real gateway look newly-unknown."""
    state["known_gateways"] = {
        gw.uid: {"name": gw.name, "version": gw.version} for gw in gateways
    }


def is_known_gateway(state: dict, uid: str) -> bool:
    return uid in state.get("known_gateways", {})
