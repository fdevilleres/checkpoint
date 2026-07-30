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
import cpadvisories
import hotfix
import skfix

_CP_RELEVANT_PRODUCTS_LOWER = {p.lower() for p in cpadvisories.DEFAULT_RELEVANT_PRODUCTS}

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
    sk_url: str | None = None
    # gateway uid -> (installed_take, required_take), only populated for the
    # sk-article/Take-based path -- lets drafter.py show the precise patch gap.
    gateway_take_gap: dict[str, tuple[int, int]] = field(default_factory=dict)
    # subset of matched_gateways with no Take fix at all (EOS version) -- needs an
    # upgrade, not a hotfix install; drafter.py renders these with a different message.
    eos_gateway_uids: set[str] = field(default_factory=set)
    # gateway uid -> max_vulnerable_take, for gateways with a known Take threshold that
    # couldn't be confirmed against the actually-installed Take (ENABLE_HOTFIX_CHECK
    # off, or the diagnostic didn't return a usable answer). Still attributable to
    # this specific gateway -- distinct from a generic "needs review" with no
    # gateway attached at all.
    gateway_known_threshold: dict[str, int] = field(default_factory=dict)


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


def _match_via_cp_advisory(adv: Advisory, gateways: list[Gateway], client, target: str | None,
                            enable_hotfix_check: bool, take_cache: dict[str, int | None],
                            relevant_products_lower: set[str] = _CP_RELEVANT_PRODUCTS_LOWER) -> MatchResult | None:
    """Top-priority path: Check Point's own structured Security Advisories API
    (cpadvisories.py) gives exact per-version Take cutoffs -- far more precise and
    reliable to fetch than scraping individual sk articles (no WAF-challenge risk,
    confirmed live). Returns None only if this advisory has no rows for any product
    this tool tracks at all (relevant_products_lower) -- once it's confirmed relevant,
    always returns a MatchResult (even an ambiguous one, with sk_url attached) rather
    than silently deferring to a fallback that has no idea this CVE is Check
    Point-relevant.

    A gateway version with no matching row in this advisory's table is treated as
    "not yet assessed" (contributes nothing either way), not "confirmed clean" --
    Check Point actively extends these tables to newer versions over time, confirmed
    live by comparing `updated` timestamps against which version rows exist.
    """
    relevant = [r for r in adv.cp_advisory_rows if r.product_name.lower() in relevant_products_lower]
    if not relevant:
        return None

    rows_by_version: dict[str, list] = {}
    for r in relevant:
        rows_by_version.setdefault(r.version, []).append(r)

    matched: list[Gateway] = []
    eos_uids: set[str] = set()
    take_gap: dict[str, tuple[int, int]] = {}
    known_threshold: dict[str, int] = {}
    any_never = False

    for gw in gateways:
        gw_version = (gw.version or "").upper().strip()
        rows = rows_by_version.get(gw_version) if gw_version else None
        if not rows:
            # No row for this gateway's exact version -- "not yet assessed" by
            # Check Point's own feed, not "confirmed clean". Contributes nothing
            # either way; falls into the ambiguous branch below if every gateway
            # ends up here (see module docstring / _match_via_cp_advisory docstring).
            continue

        confirmed_vulnerable = False
        unconfirmed_take: int | None = None
        has_unconfirmed_generic = False
        gw_never = False

        for row in rows:
            if row.status == cpadvisories.RowStatus.NEVER_VULNERABLE:
                gw_never = True
            elif row.status == cpadvisories.RowStatus.ALWAYS_VULNERABLE:
                confirmed_vulnerable = True
                eos_uids.add(gw.uid)
            elif row.status == cpadvisories.RowStatus.TAKE_BOUNDED:
                if enable_hotfix_check and client is not None and (gw.target or target):
                    if gw.uid not in take_cache:
                        take_cache[gw.uid] = hotfix.get_installed_jhf_take(client, gw.target or target, gw.name)
                    installed = take_cache[gw.uid]
                    if installed is None:
                        unconfirmed_take = row.max_vulnerable_take
                    elif installed <= row.max_vulnerable_take:
                        confirmed_vulnerable = True
                        take_gap[gw.uid] = (installed, row.max_vulnerable_take + 1)
                    # else: installed > max_vulnerable_take -> already patched
                else:
                    # Hotfix check disabled -- we still know the exact Take threshold
                    # for THIS gateway's exact version, just can't confirm what's
                    # installed. That's a real, attributable finding for this specific
                    # gateway, not a generic "could apply somewhere" ambiguity.
                    unconfirmed_take = row.max_vulnerable_take
            else:  # NEEDS_MANUAL_CHECK -- relevant to this gateway, but no numeric data
                has_unconfirmed_generic = True

        if confirmed_vulnerable:
            matched.append(gw)
        elif unconfirmed_take is not None:
            matched.append(gw)
            known_threshold[gw.uid] = unconfirmed_take
        elif has_unconfirmed_generic:
            matched.append(gw)
        elif gw_never:
            any_never = True

    if not matched and not any_never:
        # This advisory does cover gateway/management-relevant products (checked via
        # `relevant` above) -- either no current gateway's version has a row in this
        # advisory's table yet (none matched anything above), or none of the ones
        # that did resolved to a confirmed/never-vulnerable state. Either way that's
        # still real, useful context (a genuine Check Point advisory exists for this
        # CVE) worth surfacing with its sk_url, rather than returning None and
        # losing all of that to a generic, context-free fallback.
        return MatchResult(advisory=adv, matched_gateways=[], needs_review=True, sk_url=adv.source_url)

    unconfirmed_uids = {gw.uid for gw in matched} - set(take_gap) - eos_uids
    return MatchResult(
        advisory=adv,
        matched_gateways=matched,
        needs_review=bool(unconfirmed_uids),
        resolved_not_applicable=(not matched and any_never),
        sk_url=adv.source_url,
        gateway_take_gap=take_gap,
        eos_gateway_uids=eos_uids,
        gateway_known_threshold=known_threshold,
    )


def _match_via_cpe_range(adv: Advisory, gateways: list[Gateway], keywords: list[str],
                          cpe_ranges: list[CpeRange] | None = None) -> MatchResult | None:
    """NVD CPE version-range heuristic. Normally reads adv.cpe_ranges, but accepts an
    explicit override so a cp_advisory-sourced Advisory (which carries no CPE data of
    its own) can still be checked against a lazily-fetched NVD lookup. Returns None if
    there's nothing usable to reason from (manual entries, or no Check Point CPE rows)."""
    ranges = adv.cpe_ranges if cpe_ranges is None else cpe_ranges
    cp_ranges = [r for r in ranges if _is_checkpoint_cpe(r, keywords)]
    if adv.source == "manual" or not cp_ranges:
        return None

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
        return MatchResult(
            advisory=adv,
            matched_gateways=matched,
            needs_review=(undetermined and not matched) or uncertain_product,
        )
    # Real CPE version data existed and every gateway definitively fell outside the
    # vulnerable range(s) -- not "unclear," a confident "does not apply here."
    return MatchResult(advisory=adv, matched_gateways=[], resolved_not_applicable=True)


def _match_via_sk(adv: Advisory, gateways: list[Gateway], client, target: str,
                   take_cache: dict[str, int | None]) -> MatchResult | None:
    """Authoritative path: Check Point's own sk article says exactly which JHF Take
    fixes this CVE per version branch, and a bounded read-only diagnostic (hotfix.py)
    reports what's actually installed. Returns None if no linked sk article yielded
    usable Take data -- caller should fall back to the CPE-range heuristic instead
    of guessing from this path.
    """
    sk_info = None
    for url in adv.checkpoint_sk_urls:
        info = skfix.fetch_sk_fix_info(url)
        if info and info.required_takes:
            sk_info = info
            break
    if sk_info is None:
        return None

    vulnerable = []
    take_gap: dict[str, tuple[int, int]] = {}
    any_ambiguous = False
    for gw in gateways:
        gw_version = (gw.version or "").upper().strip()
        if not gw_version:
            continue
        if gw_version in sk_info.required_takes:
            required = sk_info.required_takes[gw_version]
            if gw.uid not in take_cache:
                take_cache[gw.uid] = hotfix.get_installed_jhf_take(client, gw.target or target, gw.name)
            installed = take_cache[gw.uid]
            if installed is None:
                any_ambiguous = True
            elif installed < required:
                vulnerable.append(gw)
                take_gap[gw.uid] = (installed, required)
            # else: installed >= required -> already patched, no action for this gateway
        elif gw_version in sk_info.affected_versions:
            # In scope per Check Point's own metadata, but this article gives no
            # Take number for this specific version branch -- genuinely ambiguous,
            # not something to guess at.
            any_ambiguous = True
        # else: gw_version isn't even in this advisory's affected-version list --
        # Check Point's own data says this gateway is out of scope for this CVE.

    return MatchResult(
        advisory=adv,
        matched_gateways=vulnerable,
        needs_review=any_ambiguous and not vulnerable,
        resolved_not_applicable=not vulnerable and not any_ambiguous,
        sk_url=sk_info.sk_url,
        gateway_take_gap=take_gap,
    )


def match(advisories: list[Advisory], gateways: list[Gateway], keywords: list[str],
          *, client=None, target: str | None = None, enable_hotfix_check: bool = False,
          cp_relevant_products: tuple[str, ...] | None = None,
          nvd_cpe_lookup=None) -> list[MatchResult]:
    """nvd_cpe_lookup: optional cve_id -> list[CpeRange] callback. Used only when
    Check Point's own advisory feed has relevant product rows but none cover any
    current gateway's exact version yet -- a cp_advisory-sourced Advisory carries no
    CPE data of its own, so without this the tool can't tell "not yet assessed by
    Check Point" apart from "genuinely doesn't apply," even when NVD's independent
    CPE ranges would resolve it. Called lazily (only for that ambiguous case), not
    for every advisory, to avoid an NVD round-trip per run."""
    take_cache: dict[str, int | None] = {}
    relevant_products_lower = (
        {p.lower() for p in cp_relevant_products} if cp_relevant_products else _CP_RELEVANT_PRODUCTS_LOWER
    )
    results = []
    for adv in advisories:
        cp_result = None
        if adv.cp_advisory_rows:
            cp_result = _match_via_cp_advisory(adv, gateways, client, target, enable_hotfix_check, take_cache,
                                                relevant_products_lower)

        if cp_result is not None:
            cp_pending = (cp_result.needs_review and not cp_result.matched_gateways
                          and not cp_result.resolved_not_applicable)
            if cp_pending and nvd_cpe_lookup is not None:
                extra_ranges = nvd_cpe_lookup(adv.cve_id)
                if extra_ranges:
                    cpe_result = _match_via_cpe_range(adv, gateways, keywords, cpe_ranges=extra_ranges)
                    if cpe_result is not None and (cpe_result.matched_gateways or cpe_result.resolved_not_applicable):
                        # NVD's independent version data resolved what Check Point's
                        # own feed hasn't published a row for yet -- keep the sk_url
                        # from the cp_advisory attempt so the fix reference isn't lost.
                        cpe_result.sk_url = cp_result.sk_url
                        results.append(cpe_result)
                        continue
            results.append(cp_result)
            continue
            # Check Point's own advisory feed had this CVE, but no row covered any
            # current gateway version, and NVD couldn't resolve it either.

        if enable_hotfix_check and adv.checkpoint_sk_urls and client is not None and target:
            sk_result = _match_via_sk(adv, gateways, client, target, take_cache)
            if sk_result is not None:
                results.append(sk_result)
                continue
            # sk article(s) linked but none yielded usable Take data -- fall through
            # to the CPE-range heuristic below, same as an advisory with no sk link.

        cpe_result = _match_via_cpe_range(adv, gateways, keywords)
        if cpe_result is not None:
            results.append(cpe_result)
        else:
            # No structured version data (manual ingestion, or a KEV entry that
            # couldn't be enriched with NVD CPE data) — flag for human review
            # rather than guessing which gateways are affected.
            results.append(MatchResult(advisory=adv, matched_gateways=[], needs_review=True))

    return results
