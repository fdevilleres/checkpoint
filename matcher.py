"""Matches advisories against the current gateway inventory.

Version comparison is pragmatic rather than a full CPE-compliance engine: it pulls the
numeric groups out of a version string (handles Gaia's "R81.20" as well as plain
"81.20" from NVD's CPE dictionary) and compares them as tuples. Advisories that can't
be reliably matched (no CPE data, or a vendor/product that isn't Check Point) are still
surfaced with needs_review=True instead of being silently dropped — a human should
glance at them rather than have the tool guess wrong.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field

from assets import Gateway
from feeds import Advisory, CpeRange

_NUM_RE = re.compile(r"\d+")

# Client-side/desktop products that a Gateway/server object from
# "show-gateways-and-servers" can never actually be running. Check Point reuses
# "R81.x"-style version branding loosely across unrelated product lines, so without
# this exclusion a CVE affecting e.g. SmartConsole (a Windows desktop app) can spuriously
# match a gateway just because both happen to use the string "r81.20" as a version.
_NON_GATEWAY_PRODUCT_HINTS = ("smartconsole", "smartprovisioning", "endpoint", "capsule", "harmony")

# CPE products that clearly describe an enforcement gateway/Gaia OS, vs. products like
# "quantum_security_management" or "multi-domain_security_management" that describe a
# *management server* — a different asset type than what "gateway.type" typically means
# here. A version match against the latter is still worth surfacing, but should be
# flagged for human confirmation of the object's actual role rather than treated as
# a confident match.
_GATEWAY_PRODUCT_HINTS = ("gateway", "gaia")


@dataclass
class MatchResult:
    advisory: Advisory
    matched_gateways: list[Gateway] = field(default_factory=list)
    needs_review: bool = False
    resolved_not_applicable: bool = False


def _version_tuple(version: str) -> tuple[int, ...] | None:
    nums = [int(n) for n in _NUM_RE.findall(version or "")]
    return tuple(nums) if nums else None


def _is_checkpoint_cpe(cpe: CpeRange, keywords: list[str]) -> bool:
    haystack = f"{cpe.vendor} {cpe.product}".replace("_", " ").lower()
    if not any(k.lower() in haystack for k in keywords):
        return False
    return not any(hint in cpe.product.lower() for hint in _NON_GATEWAY_PRODUCT_HINTS)


def _is_gateway_relevant_product(cpe: CpeRange) -> bool:
    return any(hint in cpe.product.lower() for hint in _GATEWAY_PRODUCT_HINTS)


def _version_in_range(gw_version: str, cpe: CpeRange) -> bool | None:
    gw_tuple = _version_tuple(gw_version)
    if gw_tuple is None:
        return None

    if cpe.exact_version:
        exact_tuple = _version_tuple(cpe.exact_version)
        return exact_tuple is not None and gw_tuple == exact_tuple

    has_bound = False
    if cpe.version_start_including:
        has_bound = True
        start = _version_tuple(cpe.version_start_including)
        if start is not None and gw_tuple < start:
            return False
    if cpe.version_end_excluding:
        has_bound = True
        end = _version_tuple(cpe.version_end_excluding)
        if end is not None and gw_tuple >= end:
            return False
    if cpe.version_end_including:
        has_bound = True
        end = _version_tuple(cpe.version_end_including)
        if end is not None and gw_tuple > end:
            return False

    return True if has_bound else None


def match(advisories: list[Advisory], gateways: list[Gateway], keywords: list[str]) -> list[MatchResult]:
    results = []
    for adv in advisories:
        cp_ranges = [r for r in adv.cpe_ranges if _is_checkpoint_cpe(r, keywords)]

        if adv.source == "manual" or not cp_ranges:
            # No structured version data (manual ingestion, or a KEV entry that
            # couldn't be enriched with NVD CPE data) — flag for human review
            # rather than guessing which gateways are affected.
            results.append(MatchResult(advisory=adv, matched_gateways=[], needs_review=True))
            continue

        matched = []
        undetermined = False
        uncertain_product = False
        for gw in gateways:
            gw_matched = False
            for r in cp_ranges:
                outcome = _version_in_range(gw.version, r)
                if outcome is True:
                    gw_matched = True
                    if not _is_gateway_relevant_product(r):
                        uncertain_product = True
                elif outcome is None:
                    undetermined = True
            if gw_matched:
                matched.append(gw)

        if matched or undetermined:
            results.append(MatchResult(
                advisory=adv,
                matched_gateways=matched,
                needs_review=(undetermined and not matched) or uncertain_product,
            ))
        else:
            # Real CPE version data existed and every gateway definitively fell
            # outside the vulnerable range(s) — not "unclear," a confident "does
            # not apply here." Worth recording as resolved so it's visible in the
            # dashboard, rather than silently vanishing.
            results.append(MatchResult(advisory=adv, matched_gateways=[], resolved_not_applicable=True))

    return results
