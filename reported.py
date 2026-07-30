"""Self-reported gateways: the credential-free path for orgs whose management
server this instance can't (or shouldn't) log into.

An admin runs gateway-report.sh from their own SmartConsole's script repository
against a gateway object. The script executes on the gateway using the admin's
already-authenticated SmartConsole session, collects the Gaia version and the
installed Jumbo Hotfix Take locally, and POSTs them to this server's /api/report.
No Management API credentials ever change hands.

Reports live in reported.json -- deliberately a separate file from state.json,
which gets overwritten wholesale whenever the operator syncs a fresh copy from
the machine that runs `main.py check`. Matching for reported gateways happens
live at request time (matcher.match with a prefilled take_cache), against the
same Check Point advisory feed + NVD fallback as the polled path.

Trust model: reports are as unauthenticated as the rest of this dashboard --
anyone who can reach the server can claim to be any gateway. Fine for a trusted
test group; revisit before wider exposure."""

from __future__ import annotations
import json
import os
import re
import threading
import time

import cpadvisories
import feeds
import matcher
import skfix
import store
from assets import Gateway

# Everything in this module runs inside a dashboard request, so sk-article lookups
# must be served from cache or skipped -- never fetched inline. An uncached article
# costs an HTTP timeout plus a retry delay, and a gateway needing ten of them made
# the Advisories tab hang for over a minute (measured live: 60s+ uncached vs 0.3s
# cached). A cache miss now degrades instantly to the approximate threshold value
# instead. `main.py check` runs without this flag and is what fills the cache.
skfix.CACHE_ONLY = True

_REPORTS_PATH = os.path.join(os.path.dirname(__file__), "reported.json")
_VERSION_RE = re.compile(r"^R\d+(\.\d+)*$")
_lock = threading.Lock()

# One shared fetch of Check Point's advisory feed per _CACHE_TTL, not one per
# dashboard request. NVD single-CVE lookups piggyback on the same cache dict.
_CACHE_TTL = 900.0
_cache: dict = {"fetched_at": 0.0, "advisories": None, "nvd_ranges": {}}

# A reported gateway was never assigned a management UID by us, so it gets a
# synthetic one -- stable per name, never colliding with real Check Point GUIDs.
_UID_PREFIX = "reported:"


def _load_reports() -> dict:
    if not os.path.exists(_REPORTS_PATH):
        return {}
    with open(_REPORTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_report(name: str, version: str, take) -> tuple[bool, str]:
    """Validates and persists one self-report. Returns (ok, message)."""
    name = (name or "").strip()
    version = (version or "").strip().upper()
    if not name or len(name) > 128:
        return False, "missing or oversized 'name'"
    if not _VERSION_RE.match(version):
        return False, "'version' must look like R82.10"
    if take is not None:
        try:
            take = int(take)
        except (TypeError, ValueError):
            return False, "'take' must be an integer or null"
        if take < 0 or take > 10000:
            return False, "'take' out of range"
    with _lock:
        reports = _load_reports()
        reports[name.lower()] = {
            "name": name,
            "version": version,
            "take": take,
            "reported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with open(_REPORTS_PATH, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
    return True, "ok"


def get_report(name: str) -> dict | None:
    return _load_reports().get((name or "").strip().lower())


def _current_advisories() -> list:
    now = time.time()
    if _cache["advisories"] is None or now - _cache["fetched_at"] > _CACHE_TTL:
        fixes = cpadvisories.fetch_all()
        advisories = []
        for fix in fixes:
            advisories.append(feeds.Advisory(
                cve_id=fix.cve_id, title=fix.cve_id, summary=fix.summary,
                source_url=fix.sk_url, source="cp_advisory",
                severity=fix.cp_severity, cvss=fix.cvss, published=fix.published,
                cp_advisory_rows=fix.rows, cp_severity=fix.cp_severity, sk_id=fix.sk_id,
            ))
        _cache["advisories"] = advisories
        _cache["fetched_at"] = now
        _cache["nvd_ranges"] = {}
    return _cache["advisories"]


def _nvd_cpe_lookup(cve_id: str) -> list:
    if cve_id not in _cache["nvd_ranges"]:
        detail = feeds.fetch_nvd_by_id(cve_id, api_key=os.getenv("NVD_API_KEY", "").strip() or None)
        _cache["nvd_ranges"][cve_id] = detail.cpe_ranges if detail else []
    return _cache["nvd_ranges"][cve_id]


RECENT_DAYS = 180


def _relevant_advisories(version: str) -> list:
    """The polled path only ever matches CVEs inside its flood-protection window;
    mirror that here rather than matching the entire ~150-advisory active catalog.
    Keep an advisory if it has an explicit row for this exact version (bounded,
    meaningful either way it resolves) or if it's recent enough that a human
    would want it surfaced even unresolved. Bounds the per-request NVD fallback
    lookups to the recent-ambiguous handful, not a hundred historical entries."""
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - RECENT_DAYS * 86400))
    keep = []
    for adv in _current_advisories():
        has_version_row = any(r.version == version for r in adv.cp_advisory_rows)
        if has_version_row or (adv.published or "") >= cutoff:
            keep.append(adv)
    return keep


def advisories_for(name: str) -> dict | None:
    """Full dashboard payload for a self-reported gateway, in the exact shape
    /api/gateway/<uid>/advisories serves for polled gateways -- advisories.js
    renders both identically. Returns None if no report exists for this name."""
    report = get_report(name)
    if report is None:
        return None

    uid = _UID_PREFIX + report["name"].lower()
    gw = Gateway(name=report["name"], uid=uid, type="simple-gateway",
                 version=report["version"], target="")
    take_cache = {uid: report["take"]}

    results = matcher.match(
        _relevant_advisories(report["version"]), [gw], ["check point", "checkpoint", "gaia"],
        # A non-None client + target makes the Take-comparison branch run; the
        # prefilled take_cache guarantees no Management API call ever happens.
        client=object(), target="reported", enable_hotfix_check=True,
        nvd_cpe_lookup=_nvd_cpe_lookup, take_cache=take_cache,
    )

    ephemeral = {"seen_cve_ids": [], "last_checked": {}, "results": {}}
    for r in results:
        store.record_result(ephemeral, r)
    return {
        "matched": store.results_for_gateway(ephemeral, uid),
        "unassigned": store.unassigned_results(ephemeral),
        "resolved": store.resolved_results(ephemeral),
        "reported": {"name": report["name"], "version": report["version"],
                      "take": report["take"], "reported_at": report["reported_at"]},
    }
