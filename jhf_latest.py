"""Fetches Check Point's own Jumbo Hotfix Accumulator downloads page per major
version and reads off the LATEST available Take -- distinct from the Take that
fixes any specific CVE (skfix.py) and distinct from Check Point's own
"Recommended" designation, which can lag "Latest" by several Takes while a new
release accumulates field validation (confirmed live: R82.10's page lists
"Take 36 - Latest" alongside "Take 24 - Recommended" from a month earlier).

This tool always points at the latest available Take, not just whatever Take
happens to fix one CVE -- an org already ahead of a CVE's fix Take on general
hotfixes shouldn't be told to chase an old, superseded number.

Server-rendered, publicly readable, no login needed -- same as skfix.py's sk
articles. Cached on disk for the same reason: avoid a network call on every
dashboard load, since new Takes ship on the order of weeks, not minutes.
"""

from __future__ import annotations
import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass

_URL_TEMPLATE = "https://sc1.checkpoint.com/documents/Jumbo_HFA/{v}/{v}/{v}_Downloads.htm"
# Confirmed live: "<h3>Take 36 - Latest</h3>" (R82.10). The "Recommended" entry's
# label is itself wrapped in an inner <span>, so allow (but don't require) tags
# between the dash and the word, in case "Latest" ever gets the same treatment.
_LATEST_RE = re.compile(r"<h3\b[^>]*>\s*Take\s*(\d+)\s*-\s*(?:<[^>]+>\s*)*Latest", re.IGNORECASE)

_CACHE_PATH = os.path.join(os.path.dirname(__file__), "jhf_latest_cache.json")
_CACHE_TTL = 7 * 24 * 3600.0  # new Takes ship on the order of weeks

# Same purpose as skfix.CACHE_ONLY: set True by reported.py so a cache miss inside
# a user-facing dashboard request degrades instantly instead of making a live
# HTTP call and hanging the tab.
CACHE_ONLY = False


@dataclass
class JhfLatestInfo:
    version: str
    latest_take: int | None


def _load_cache() -> dict:
    if not os.path.exists(_CACHE_PATH):
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_get(version: str) -> JhfLatestInfo | None:
    entry = _load_cache().get(version)
    if not entry or time.time() - entry.get("cached_at", 0) > _CACHE_TTL:
        return None
    return JhfLatestInfo(version=version, latest_take=entry.get("latest_take"))


def _cache_put(info: JhfLatestInfo) -> None:
    cache = _load_cache()
    cache[info.version] = {"cached_at": time.time(), "latest_take": info.latest_take}
    try:
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def fetch_latest_take(version: str, use_cache: bool = True) -> JhfLatestInfo | None:
    """Returns None on fetch failure, or if this version has no JHF downloads page
    at all (e.g. an end-of-support version Check Point no longer ships Takes for).
    Cached for a week -- same rationale as skfix.py."""
    version = (version or "").upper().strip()
    if not version:
        return None
    if use_cache:
        cached = _cache_get(version)
        if cached is not None:
            return cached

    if CACHE_ONLY:
        return None

    url = _URL_TEMPLATE.format(v=version)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (advisory-watch/1.0)"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

    match = _LATEST_RE.search(html)
    info = JhfLatestInfo(version=version, latest_take=int(match.group(1)) if match else None)
    if use_cache:
        _cache_put(info)
    return info
