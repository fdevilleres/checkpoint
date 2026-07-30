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

# The section heading is the anchor, NOT a bare string search: the same heading text
# also appears in the article's table of contents and in revision-history entries
# (4 occurrences of the plain string on sk185033, but exactly one real <h3>).
_H3_BLOCK_RE = re.compile(r"<h3\b[^>]*>(.*?)</h3>", re.IGNORECASE | re.DOTALL)
# Fallback anchor: the sentence that introduces the fix table.
_FIX_SENTENCE = "The fix is included in these Jumbo Hotfix Accumulator"

_TABLE_RE = re.compile(r"<table\b.*?</table>", re.IGNORECASE | re.DOTALL)
_ROW_RE = re.compile(r"<tr\b.*?</tr>", re.IGNORECASE | re.DOTALL)
_CELL_RE = re.compile(r"<t[dh]\b.*?</t[dh]>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_H3_RE = re.compile(r"<h3\b", re.IGNORECASE)

_VERSION_IN_CELL_RE = re.compile(r"(R\d+(?:\.\d+)?)\s*Jumbo Hotfix Accumulator", re.IGNORECASE)
_TAKE_IN_CELL_RE = re.compile(r"Take\s*(\d+)", re.IGNORECASE)
# Prose form, only ever applied inside the already-scoped Solution section.
_PROSE_FIX_RE = re.compile(
    r"(R\d+(?:\.\d+)?)\s*Jumbo Hotfix Accumulator\s*(?:Take|.{0,20}?Take)\s*(\d+)",
    re.IGNORECASE,
)

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
    """The slice of HTML from the Solution section's JHF-fix <h3> up to the next
    <h3>. Everything outside this window (the vulnerable-configs list, the "Hotfix"
    download table, revision history) mentions Take numbers that are not the fix,
    so scoping here is what makes the parse correct rather than coincidental."""
    start = None
    for heading in _H3_BLOCK_RE.finditer(html):
        text = _strip(heading.group(1)).lower()
        if "jumbo hotfix accumulator" in text and ("install" in text or "recommended" in text):
            start = heading.end()
            break

    if start is None:
        # No matching heading -- fall back to the sentence that introduces the
        # table. Still anchored inside the Solution body, never the TOC.
        idx = html.find(_FIX_SENTENCE)
        if idx == -1:
            return None
        start = idx

    next_h3 = _H3_RE.search(html, start)
    return html[start:next_h3.start()] if next_h3 else html[start:]


def _parse_fix_takes(html: str) -> dict[str, int]:
    section = _extract_fix_section(html)
    if section is None:
        return {}

    fix_takes: dict[str, int] = {}
    table_match = _TABLE_RE.search(section)
    if table_match:
        for row_html in _ROW_RE.findall(table_match.group(0)):
            cells = [_strip(c) for c in _CELL_RE.findall(row_html)]
            if len(cells) < 2:
                continue
            version_match = _VERSION_IN_CELL_RE.search(cells[0])
            take_match = _TAKE_IN_CELL_RE.search(cells[1])
            if version_match and take_match:
                fix_takes[version_match.group(1).upper()] = int(take_match.group(1))

    if not fix_takes:
        # No table in this section -- some articles state the recommended Take as
        # prose instead. Still scoped to the Solution section, so this can't pick
        # up a download-table or revision-history number.
        for version, take in _PROSE_FIX_RE.findall(_strip(section)):
            fix_takes[version.upper()] = int(take)

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
