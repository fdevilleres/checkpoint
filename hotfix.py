"""Determines a gateway's actually-installed Jumbo Hotfix Accumulator (JHF) Take
via the Check Point Management API's show-software-packages-per-targets -- a
pure read-only query against the management server itself (nothing executes on
the gateway), gated behind ENABLE_HOTFIX_CHECK in .env (default off).

Replaces an earlier run-script + cpinfo-scraping approach. Cross-checked live
against three real gateways: agreed exactly in all three cases (two reporting
no installed hotfix, one reporting Take 20)."""

from __future__ import annotations
import re

from cp_client import CPClient

# The Take number is the last underscore-delimited token before the file
# extension, e.g. "..._JHF_MAIN_Bundle_aarch64_T20_FULL.tgz" -> 20. Earlier
# T<digits> tokens in the same package-id can be unrelated build/EA tags (e.g.
# "T313" in "Check_Point_R82_20_T313_EA_JHF_MAIN_Bundle_..._T20_FULL.tgz"),
# so only the end-anchored one is trusted.
_TAKE_RE = re.compile(r"_T(\d+)(?:_FULL)?\.tgz$", re.IGNORECASE)

# The base-OS installer/upgrade package ("major" category) also carries a
# trailing build tag that looks like a Take number but isn't one -- exclude it.
_EXCLUDED_CATEGORIES = {"major"}


def get_installed_jhf_take(client: CPClient, target: str, gateway_name: str, poll_timeout: float = 30.0) -> int | None:
    """Returns the installed JHF Take number (0 if no hotfix package is installed
    at all), or None if the query failed or no Take-shaped package-id was found
    among installed, non-excluded packages. Never raises -- callers should treat
    None as "couldn't determine, fall back to manual review", not as an error.
    poll_timeout is accepted for call-site compatibility but unused -- this is a
    single synchronous query, not an async task to poll."""
    try:
        resp = client.call("show-software-packages-per-targets", target, {
            "targets": [gateway_name],
            "display": {"installed": "yes"},
        })
        packages = resp["targets"][0]["packages"]["installed"]
    except Exception:
        return None

    if not packages:
        return 0

    takes = []
    for pkg in packages:
        if pkg.get("category") in _EXCLUDED_CATEGORIES:
            continue
        m = _TAKE_RE.search(pkg.get("package-id", ""))
        if m:
            takes.append(int(m.group(1)))
    return max(takes) if takes else None
