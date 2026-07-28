"""Fetches and parses Check Point's own public, structured Security Advisories API --
the primary source for "which CVEs affect Check Point products and what Jumbo Hotfix
Take number fixes each one." Unauthenticated, no WAF challenge observed (unlike
scraping individual sk articles -- see skfix.py), returns the full active-advisory
catalog in one call. https://support.checkpoint.com/security-advisories is the
human-facing page this API actually powers."""

from __future__ import annotations
import json
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

API_URL = "https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive"

# Product lines that map onto what this tool's gateway/management-server objects
# actually run. Excludes desktop/endpoint-only products (SmartConsole, Harmony *,
# Endpoint Security Client/VPN, SSL Network Extender) for the same reason
# matcher.py's _NON_GATEWAY_PRODUCT_HINTS excludes them from CPE matching.
DEFAULT_RELEVANT_PRODUCTS = (
    "Security Gateways", "Quantum Security Gateways", "Quantum Appliances",
    "Quantum Maestro", "Quantum Scalable Chassis",
    "Security Management", "Quantum Security Management", "Multi-Domain Security Management",
    "Quantum Smart-1", "VSX (Traditional)", "ClusterXL",
    "CloudGuard Network", "CloudGuard Network for AWS", "CloudGuard Network for Azure",
    "Remote Access VPN", "Site-to-Site VPN", "Mobile Access / SSL VPN", "Mobile Access",
    "IPS", "Identity Awareness", "HTTPS Inspection",
)


class RowStatus(Enum):
    NEVER_VULNERABLE = "never_vulnerable"       # affected == "None"
    ALWAYS_VULNERABLE = "always_vulnerable"     # affected == "All" (typically EOS, no fix Take exists)
    TAKE_BOUNDED = "take_bounded"               # a specific Take number resolves it
    NEEDS_MANUAL_CHECK = "needs_manual_check"   # "Details in SK", third-party CVE, or an unparsed phrasing


@dataclass
class ProductRow:
    product_name: str
    version: str          # normalized, e.g. "R82.10" -- EOS/GA suffix stripped
    is_eos: bool
    status: RowStatus
    max_vulnerable_take: int | None = None   # only set when status == TAKE_BOUNDED
    raw_affected: str = ""


@dataclass
class AdvisoryFix:
    cve_id: str
    summary: str
    cvss: float | None
    cp_severity: str
    sk_id: str
    sk_url: str
    published: str
    updated: str
    rows: list[ProductRow] = field(default_factory=list)

    def relevant_rows(self, allowed_products: tuple[str, ...] = DEFAULT_RELEVANT_PRODUCTS) -> list[ProductRow]:
        allowed_lower = {p.lower() for p in allowed_products}
        return [r for r in self.rows if r.product_name.lower() in allowed_lower]


_VERSION_SUFFIX_RE = re.compile(r"^(.*?)\s*\((EOS|GA)\)\s*$", re.IGNORECASE)

# The two Take-based phrasings observed live have DIFFERENT off-by-one semantics --
# confirmed by comparing the same underlying CVE described both ways. "Prior to JHF
# Take 65" (older phrasing, e.g. CVE-2024-24919/sk182336) means Take 65 itself is
# already fixed. "Take 118 or below" (newer phrasing, e.g. CVE-2026-16232/sk185169)
# means Take 118 itself is STILL vulnerable -- the fix is Take 119. Both are
# normalized below into one "highest still-vulnerable Take" number so callers never
# have to reason about phrasing, only compare installed_take <= max_vulnerable_take.
_PRIOR_TO_TAKE_RE = re.compile(r"prior to (?:jhf\s+)?take\s+(\d+)", re.IGNORECASE)
_TAKE_OR_BELOW_RE = re.compile(r"take\s+(\d+)\s+or\s+below", re.IGNORECASE)


def _normalize_version(raw: str) -> tuple[str, bool]:
    """Returns (version, is_eos), stripping a trailing "(EOS)"/"(GA)" annotation."""
    m = _VERSION_SUFFIX_RE.match((raw or "").strip())
    if m:
        return m.group(1).strip().upper(), m.group(2).upper() == "EOS"
    return raw.strip().upper(), False


def _parse_affected(raw: str) -> tuple[RowStatus, int | None]:
    text = (raw or "").strip()
    if text.lower() == "none":
        return RowStatus.NEVER_VULNERABLE, None
    if text.lower() == "all":
        return RowStatus.ALWAYS_VULNERABLE, None
    m = _PRIOR_TO_TAKE_RE.search(text)
    if m:
        return RowStatus.TAKE_BOUNDED, int(m.group(1)) - 1
    m = _TAKE_OR_BELOW_RE.search(text)
    if m:
        return RowStatus.TAKE_BOUNDED, int(m.group(1))
    return RowStatus.NEEDS_MANUAL_CHECK, None


def _ms_to_iso(ms) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_all() -> list[AdvisoryFix]:
    """Fetches every active Check Point security advisory in one call. Raises on
    network failure -- unlike sk-scraping (skfix.py), this is meant to be the
    reliable always-on primary path, so callers should let failures surface rather
    than silently degrading."""
    req = urllib.request.Request(API_URL, headers={"User-Agent": "advisory-watch/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = json.loads(resp.read())

    advisories = []
    for entry in raw:
        rows = []
        for p in entry.get("products", []):
            version, is_eos = _normalize_version(p.get("version", ""))
            status, max_take = _parse_affected(p.get("affected", ""))
            rows.append(ProductRow(
                product_name=p.get("name", ""),
                version=version,
                is_eos=is_eos,
                status=status,
                max_vulnerable_take=max_take,
                raw_affected=p.get("affected", ""),
            ))
        sk_id = entry.get("skId", "")
        advisories.append(AdvisoryFix(
            cve_id=entry.get("cveId", ""),
            summary=entry.get("summary", ""),
            cvss=entry.get("cvss"),
            cp_severity=entry.get("cpSeverity", ""),
            sk_id=sk_id,
            sk_url=entry.get("url") or (f"https://support.checkpoint.com/results/sk/{sk_id}" if sk_id else ""),
            published=_ms_to_iso(entry.get("published")),
            updated=_ms_to_iso(entry.get("updated")),
            rows=rows,
        ))
    return advisories
