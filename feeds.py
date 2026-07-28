"""Fetches vendor security advisories from public feeds: CISA KEV and NVD. Also
supports manual ingestion of a specific Check Point sk-article (fetch_manual) for
cases the automated feeds miss. Check Point's own structured advisory data --
per-version Jumbo Hotfix Take cutoffs -- lives in cpadvisories.py, sourced from their
public Security Advisories API rather than scraped from individual sk pages."""

from __future__ import annotations
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_SK_URL_RE = re.compile(r"support\.checkpoint\.com/results/sk/(sk\d+)", re.IGNORECASE)


@dataclass
class CpeRange:
    vendor: str
    product: str
    version_start_including: str | None = None
    version_end_excluding: str | None = None
    version_end_including: str | None = None
    exact_version: str | None = None


@dataclass
class Advisory:
    cve_id: str
    title: str
    summary: str
    source_url: str
    source: str  # "kev" | "nvd" | "manual" | "cp_advisory"
    severity: str = ""
    cvss: float | None = None
    kev: bool = False
    published: str = ""
    cpe_ranges: list[CpeRange] = field(default_factory=list)
    raw_text: str = ""  # populated for manual advisories the matcher can't parse
    checkpoint_sk_urls: list[str] = field(default_factory=list)  # linked Check Point sk articles
    # list[cpadvisories.ProductRow] -- populated when this Advisory was built from
    # Check Point's own structured Security Advisories API (see cpadvisories.py).
    # Not typed against that module here to keep feeds.py dependency-free.
    cp_advisory_rows: list = field(default_factory=list)
    cp_severity: str = ""
    sk_id: str = ""


def _http_get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "advisory-watch/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_kev(keywords: list[str]) -> list[Advisory]:
    """Pull the CISA Known Exploited Vulnerabilities catalog, filtered by vendor/product keyword."""
    data = _http_get_json(KEV_URL)
    keywords_l = [k.lower() for k in keywords]
    advisories = []
    for vuln in data.get("vulnerabilities", []):
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        haystack = f"{vendor} {product}".lower()
        if not any(k in haystack for k in keywords_l):
            continue
        advisories.append(Advisory(
            cve_id=vuln.get("cveID", ""),
            title=f"{vendor} {product} — {vuln.get('vulnerabilityName', '')}",
            summary=vuln.get("shortDescription", ""),
            source_url=f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID', '')}",
            source="kev",
            kev=True,
            published=vuln.get("dateAdded", ""),
        ))
    return advisories


def fetch_nvd(cpe_vendors: list[str], since: str | None = None, api_key: str | None = None) -> list[Advisory]:
    """Query NVD for CVEs whose CPE configurations reference any of the given vendor
    identifiers (e.g. "checkpoint"), optionally published since a timestamp (ISO 8601,
    e.g. '2026-07-01T00:00:00.000').

    Uses `virtualMatchString` (a structured CPE-prefix match) rather than `keywordSearch`
    (a free-text search over the description) — keywordSearch on a word like "checkpoint"
    also matches unrelated CVEs that happen to use the word generically (e.g. "loading a
    model checkpoint"), which floods results with noise. Matching on the CPE vendor slug
    is precise: it only returns CVEs actually cataloged against that vendor's products.

    Filters by *publication* date (`pubStartDate`/`pubEndDate`) rather than NVD's
    `lastModStartDate` — NVD periodically re-touches metadata on decades-old CVE records
    (rescoring, CPE corrections), so "modified recently" pulls in ancient, long-since-
    patched CVEs that aren't actually new information. Publication date is what "new
    since I last checked" should mean here.
    """
    advisories: dict[str, Advisory] = {}
    headers = {"User-Agent": "advisory-watch/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    for vendor in cpe_vendors:
        match_string = f"cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*:*"
        start_index = 0
        while True:
            params = [f"virtualMatchString={urllib.parse.quote(match_string)}",
                      "resultsPerPage=200", f"startIndex={start_index}"]
            if since:
                params.append(f"pubStartDate={since}")
                params.append(f"pubEndDate={_now_iso()}")
            url = f"{NVD_URL}?{'&'.join(params)}"
            try:
                data = _http_get_json(url, headers=headers)
            except Exception:
                break
            items = data.get("vulnerabilities", [])
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id or cve_id in advisories:
                    continue
                descriptions = cve.get("descriptions", [])
                summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss, severity = _extract_cvss(metrics)
                cpe_ranges = _extract_cpe_ranges(cve.get("configurations", []))
                advisories[cve_id] = Advisory(
                    cve_id=cve_id,
                    title=cve_id,
                    summary=summary,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    source="nvd",
                    severity=severity,
                    cvss=cvss,
                    published=cve.get("published", ""),
                    cpe_ranges=cpe_ranges,
                    checkpoint_sk_urls=_extract_sk_urls(cve.get("references", [])),
                )
            total = data.get("totalResults", len(items))
            start_index += len(items)
            if start_index >= total or not items:
                break
    return list(advisories.values())


def _extract_sk_urls(references: list) -> list[str]:
    """Pulls Check Point sk-article URLs out of an NVD CVE's references array. NVD
    consistently links the vendor's own advisory for well-documented CVEs (confirmed
    live on CVE-2024-24919 -> sk182336, tagged Patch/Vendor Advisory) — this is what
    lets us go from "NVD says this CVE exists" to "here's Check Point's own fix
    guidance" without needing SupportCenter login or scraping a search UI."""
    seen = set()
    urls = []
    for ref in references or []:
        url = ref.get("url", "")
        m = _SK_URL_RE.search(url)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            urls.append(f"https://support.checkpoint.com/results/sk/{m.group(1)}")
    return urls


def _extract_cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", entries[0].get("baseSeverity", ""))
    return None, ""


def _extract_cpe_ranges(configurations: list) -> list[CpeRange]:
    ranges = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                ranges.append(CpeRange(
                    vendor=vendor,
                    product=product,
                    version_start_including=match.get("versionStartIncluding"),
                    version_end_excluding=match.get("versionEndExcluding"),
                    version_end_including=match.get("versionEndIncluding"),
                    exact_version=version if version not in ("*", "-") else None,
                ))
    return ranges


def fetch_nvd_by_id(cve_id: str, api_key: str | None = None) -> Advisory | None:
    """Fetch full NVD detail (including CPE version ranges) for a single CVE ID.
    Used to enrich KEV entries, which carry no version-range data of their own."""
    headers = {"User-Agent": "advisory-watch/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}"
    try:
        data = _http_get_json(url, headers=headers)
    except Exception:
        return None
    items = data.get("vulnerabilities", [])
    if not items:
        return None
    cve = items[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    cvss, severity = _extract_cvss(cve.get("metrics", {}))
    return Advisory(
        cve_id=cve_id,
        title=cve_id,
        summary=summary,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source="nvd",
        severity=severity,
        cvss=cvss,
        published=cve.get("published", ""),
        cpe_ranges=_extract_cpe_ranges(cve.get("configurations", [])),
        checkpoint_sk_urls=_extract_sk_urls(cve.get("references", [])),
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_manual(url_or_text: str) -> Advisory:
    """Ingest a Check Point sk-article (or any other advisory) by URL or raw pasted text.
    No structured CPE data is available here, so the result is always flagged for
    human review rather than auto-matched against gateway versions."""
    if url_or_text.strip().lower().startswith(("http://", "https://")):
        req = urllib.request.Request(url_or_text, headers={"User-Agent": "advisory-watch/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()
        source_url = url_or_text
    else:
        text = url_or_text.strip()
        source_url = ""

    cve_match = _CVE_RE.search(text)
    cve_id = cve_match.group(0) if cve_match else ""
    title = text[:120] + ("…" if len(text) > 120 else "")

    return Advisory(
        cve_id=cve_id or f"MANUAL-{abs(hash(text)) % 100000}",
        title=title,
        summary=text[:2000],
        source_url=source_url,
        source="manual",
        raw_text=text,
    )

