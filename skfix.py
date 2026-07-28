"""Fetches and parses a Check Point sk-article for its Jumbo Hotfix Accumulator (JHA)
remediation guidance -- the "which Take number actually fixes this CVE" step.

sk articles are publicly readable (confirmed live: no SupportCenter login needed) and
server-rendered (confirmed: the article content is present in the raw HTTP response,
including a clean embedded JSON blob with metadata -- no JS execution required)."""

from __future__ import annotations
import re
import time
import urllib.request
from dataclasses import dataclass, field

# Check Point consistently phrases Jumbo Hotfix remediation as e.g.
# "R81.20 Jumbo Hotfix Accumulator Recommended Take 65" -- confirmed live on
# sk182336 (CVE-2024-24919), both in the summary bullet list and the detail table.
_TAKE_RE = re.compile(
    r"(R\d+(?:\.\d+)?)\s+Jumbo Hotfix Accumulator\s+(?:Recommended\s+)?Take\s+(\d+)",
    re.IGNORECASE,
)

# The article embeds a clean JSON metadata blob, e.g.
# "versions":"R77.20 (EOS), R77.30 (EOS), ..., R81.20" -- this is the full list of
# versions the advisory considers in scope, separate from (and more reliable than)
# scraping an HTML label. A gateway version absent from this list is out of scope
# entirely; one present here but missing from _TAKE_RE's matches is in scope but not
# (yet) covered by this article's Take table -- two different "can't confirm" cases.
_VERSIONS_FIELD_RE = re.compile(r'"versions"\s*:\s*"([^"]*)"')
_VERSION_TOKEN_RE = re.compile(r"(R\d+(?:\.\d+)?)")


@dataclass
class SkFixInfo:
    sk_url: str
    required_takes: dict[str, int] = field(default_factory=dict)   # {"R81.20": 65, ...}
    affected_versions: set[str] = field(default_factory=set)       # {"R81.20", "R81.10", ...}


def fetch_sk_fix_info(sk_url: str, retries: int = 1, retry_delay: float = 5.0) -> SkFixInfo | None:
    """Returns None on fetch failure OR when Check Point's CDN bot-challenges the
    request (CloudFront + AWS WAF, seen live: HTTP 202 + empty body +
    `x-amzn-waf-action: challenge` under rapid automated requests) -- retried once
    after a short delay, since a normal `check` run only looks up a handful of sk
    articles per week and shouldn't normally trigger this. Deliberately distinct from
    "fetched fine, but this page's phrasing didn't match" (empty required_takes on a
    real SkFixInfo) -- callers should only treat the latter as "no structured data
    here", not a None caused by being rate-limited."""
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

    required_takes: dict[str, int] = {}
    for version, take in _TAKE_RE.findall(html):
        version = version.upper()
        take_n = int(take)
        # The same version's Take number is often repeated (e.g. a summary bullet
        # list plus a detailed table) -- keep the highest value seen as the most
        # current/complete guidance rather than whichever appeared first.
        if version not in required_takes or take_n > required_takes[version]:
            required_takes[version] = take_n

    affected_versions: set[str] = set()
    m = _VERSIONS_FIELD_RE.search(html)
    if m:
        affected_versions = {v.upper() for v in _VERSION_TOKEN_RE.findall(m.group(1))}

    return SkFixInfo(sk_url=sk_url, required_takes=required_takes, affected_versions=affected_versions)
