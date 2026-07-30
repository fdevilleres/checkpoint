"""Fetches a Check Point sk-article and extracts the Jumbo Hotfix Accumulator Take
that actually CONTAINS THE FIX -- read from the article's Solution section, not from
anywhere else on the page.

Why this is scoped so tightly (confirmed live against sk185033):

A single sk-article mentions "R<ver> Jumbo Hotfix Accumulator Take N" in four
different places that mean four different things:

  1. "Vulnerable Configurations": "R82.10 Jumbo Hotfix Take 19 or below"
     -> the VULNERABILITY threshold. This is what Check Point's structured
        advisories API mirrors. It is NOT the fix.
  2. Solution -> "Recommended step - Install Jumbo Hotfix Accumulator":
     "The fix is included in these Jumbo Hotfix Accumulators: R82.10 ... Take 24"
     -> THE FIX. This is the only number an admin should act on, and the only
        one this module returns.
  3. "Hotfix" download table: "R82.10 Jumbo Hotfix Accumulator Take 19 | 3 | (TAR)"
     -> standalone hotfixes that install ON TOP of an older Take. Take 19 here is
        a base, not a fix.
  4. "Revision History": historical mentions of takes added over time.

Crucially, the fix Take is NOT "vulnerable threshold + 1": for CVE-2026-50751 on
R82.10 the threshold is Take 19 but the fix only landed in Take 24. Deriving one
from the other produces a real, actionable-looking wrong answer, so this module
reads the Solution table directly and returns nothing rather than guessing.

sk articles are publicly readable (no SupportCenter login) and server-rendered, so
the Solution table is present in the raw HTTP response with no JS execution needed.
Responses are cached on disk because Check Point's CDN bot-challenges repeated
automated requests -- see fetch_sk_fix_info."""

from __future__ import annotations
import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field

# Primary anchor: the sentence that introduces the fix list, in either of the two
# phrasings seen live --
#   sk185033: "The fix is included in these Jumbo Hotfix Accumulators:"  (a table)
#   sk185169: "This problem was fixed. The fix is included in:"          (a <ul>)
_FIX_SENTENCE_RE = re.compile(r"The fix is included in", re.IGNORECASE)
# Fallback anchor: the section heading. Matched as an <h3> element rather than as
# plain text because the same heading string also appears in the article's table of
# contents and in revision-history entries (4 plain-string hits on sk185033, but
# exactly one real <h3>).
_H3_BLOCK_RE = re.compile(r"<h3\b[^>]*>(.*?)</h3>", re.IGNORECASE | re.DOTALL)

_TABLE_RE = re.compile(r"<table\b.*?</table>", re.IGNORECASE | re.DOTALL)
_LIST_RE = re.compile(r"<ul\b.*?</ul>", re.IGNORECASE | re.DOTALL)
_ROW_RE = re.compile(r"<tr\b.*?</tr>", re.IGNORECASE | re.DOTALL)
_ITEM_RE = re.compile(r"<li\b.*?</li>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_H3_RE = re.compile(r"<h3\b", re.IGNORECASE)

# Both word orders seen live, on articles published weeks apart:
#   "R82.10 Jumbo Hotfix Accumulator" ... "Take 24"        (sk185033, table)
#   "Jumbo Hotfix Accumulator for R82.10 starting from Take 36" (sk185169, list)
_VERSION_RES = (
    re.compile(r"(R\d+(?:\.\d+)?)\s*Jumbo Hotfix Accumulator", re.IGNORECASE),
    re.compile(r"Jumbo Hotfix Accumulator\s+for\s+(R\d+(?:\.\d+)?)", re.IGNORECASE),
)
_TAKE_RE = re.compile(r"Take\s*(\d+)", re.IGNORECASE)

# The full list of versions the advisory considers in scope, from the article's
# embedded metadata blob. A gateway version absent from this list is out of scope
# entirely; present here but missing from the fix table means in scope but with no
# published JHF fix -- two different "can't confirm" cases.
_VERSIONS_FIELD_RE = re.compile(r'"versions"\s*:\s*"([^"]*)"')
_VERSION_TOKEN_RE = re.compile(r"(R\d+(?:\.\d+)?)")

_CACHE_PATH = os.path.join(os.path.dirname(__file__), "sk_cache.json")
_CACHE_TTL = 7 * 24 * 3600.0  # sk articles change on the order of weeks


@dataclass
class SkFixInfo:
    sk_url: str
    # {"R82.10": 24, ...} -- the Take that CONTAINS THE FIX, from the Solution
    # section only. Empty means the article was read fine but published no JHF
    # fix table (distinct from a None return, which means it couldn't be read).
    fix_takes: dict[str, int] = field(default_factory=dict)
    affected_versions: set[str] = field(default_factory=set)


def _strip(html: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html)).strip()


def _load_cache() -> dict:
    if not os.path.exists(_CACHE_PATH):
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_get(sk_url: str) -> SkFixInfo | None:
    entry = _load_cache().get(sk_url)
    if not entry or time.time() - entry.get("cached_at", 0) > _CACHE_TTL:
        return None
    return SkFixInfo(
        sk_url=sk_url,
        fix_takes={k: int(v) for k, v in entry.get("fix_takes", {}).items()},
        affected_versions=set(entry.get("affected_versions", [])),
    )


def _cache_put(info: SkFixInfo) -> None:
    cache = _load_cache()
    cache[info.sk_url] = {
        "cached_at": time.time(),
        "fix_takes": info.fix_takes,
        "affected_versions": sorted(info.affected_versions),
    }
    try:
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _extract_fix_section(html: str) -> str | None:
    """The slice of HTML holding ONLY the "these are the Jumbo Takes that contain the
    fix" list, anchored on the sentence that introduces it and bounded by the next
    <h3>. The bound matters: on sk185033 the very next heading starts the "Hotfix"
    download table, whose rows name older base Takes that are emphatically not the
    fix. Everything else that quotes a Take (the vulnerable-configurations list,
    revision history) also falls outside this window."""
    match = _FIX_SENTENCE_RE.search(html)
    start = match.end() if match else None

    if start is None:
        for heading in _H3_BLOCK_RE.finditer(html):
            text = _strip(heading.group(1)).lower()
            if "jumbo hotfix accumulator" in text and ("install" in text or "recommended" in text):
                start = heading.end()
                break
    if start is None:
        return None

    next_h3 = _H3_RE.search(html, start)
    return html[start:next_h3.start()] if next_h3 else html[start:]


def _version_take(text: str) -> tuple[str, int] | None:
    take_match = _TAKE_RE.search(text)
    if not take_match:
        return None
    for version_re in _VERSION_RES:
        version_match = version_re.search(text)
        if version_match:
            return version_match.group(1).upper(), int(take_match.group(1))
    return None


def _parse_fix_takes(html: str) -> dict[str, int]:
    section = _extract_fix_section(html)
    if section is None:
        return {}

    # Whichever of the two containers appears first after the anchor is the fix
    # list: a <table> (sk185033) or a <ul> (sk185169).
    table_match = _TABLE_RE.search(section)
    list_match = _LIST_RE.search(section)
    candidates = [m for m in (table_match, list_match) if m]
    if not candidates:
        return {}
    block = min(candidates, key=lambda m: m.start()).group(0)

    items = _ROW_RE.findall(block) or _ITEM_RE.findall(block)
    fix_takes: dict[str, int] = {}
    for item in items:
        parsed = _version_take(_strip(item))
        if parsed:
            version, take = parsed
            fix_takes[version] = take
    return fix_takes


def fetch_sk_fix_info(sk_url: str, retries: int = 1, retry_delay: float = 5.0,
                       use_cache: bool = True) -> SkFixInfo | None:
    """Returns None on fetch failure OR when Check Point's CDN bot-challenges the
    request (CloudFront + AWS WAF, seen live: HTTP 202 + empty body +
    `x-amzn-waf-action: challenge` under repeated automated requests). Deliberately
    distinct from "read fine, but this article publishes no JHF fix table" (an
    SkFixInfo with empty fix_takes) -- only the latter means "no fix data here".

    Successful reads are cached on disk for a week. sk articles change on the order
    of weeks, and caching is what keeps a routine run from re-fetching the same
    handful of articles often enough to trip the bot challenge."""
    if use_cache:
        cached = _cache_get(sk_url)
        if cached is not None:
            return cached

    html = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(sk_url, headers={"User-Agent": "Mozilla/5.0 (advisory-watch/1.0)"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.getheader("x-amzn-waf-action") == "challenge":
                    if attempt < retries:
                        time.sleep(retry_delay)
                        continue
                    return None
                html = resp.read().decode("utf-8", errors="replace")
                break
        except Exception:
            return None
    if html is None:
        return None

    affected_versions: set[str] = set()
    m = _VERSIONS_FIELD_RE.search(html)
    if m:
        affected_versions = {v.upper() for v in _VERSION_TOKEN_RE.findall(m.group(1))}

    info = SkFixInfo(sk_url=sk_url, fix_takes=_parse_fix_takes(html),
                      affected_versions=affected_versions)
    if use_cache:
        _cache_put(info)
    return info
