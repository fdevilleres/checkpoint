"""CLI entry point for advisory-watch.

    python main.py check              # poll feeds, match, create Gmail drafts for new matches
    python main.py check --dry-run    # same, but only prints — touches nothing external
    python main.py add-advisory <url-or-text-or-file>   # manual Check Point sk-article ingestion
    python main.py send-draft <cve-id> [--to email1,email2]   # actually send an already-drafted advisory
"""

from __future__ import annotations
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

# Advisory summaries pulled from NVD can contain arbitrary Unicode (non-English CVE
# descriptions, symbols, etc.). Windows' default console codepage (cp1252) can't
# encode most of it, which would otherwise crash the whole run mid-way through
# printing a dry-run report — replace unencodable characters instead of raising.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from dotenv import load_dotenv
load_dotenv()

from cp_client import CPClient, CPTarget
from assets import list_gateways
import cpadvisories
import feeds
import matcher
import drafter
import store

TARGET_NAME = "management"


TARGETS_FILE = os.path.join(os.path.dirname(__file__), "targets.json")


def _build_targets() -> list[CPTarget]:
    """Primary management server from .env (target name 'management', unchanged),
    plus any additional servers from targets.json — one entry per management
    server/org, each with its own credentials. See targets.json.example."""
    targets: list[CPTarget] = []

    mgmt_host = os.getenv("MANAGEMENT_HOST", "").strip()
    s1c_url = os.getenv("S1C_URL", "").strip()
    if mgmt_host:
        url = f"https://{mgmt_host}:{os.getenv('MANAGEMENT_PORT', '443').strip()}"
    elif s1c_url:
        url = s1c_url
    else:
        url = None
    if url:
        targets.append(CPTarget(
            name=TARGET_NAME, url=url,
            domain=os.getenv("DOMAIN", "SMC User").strip() or "SMC User",
            api_key=os.getenv("API_KEY", "").strip() or None,
            username=os.getenv("USERNAME", "").strip() or None,
            password=os.getenv("PASSWORD", "").strip() or None,
            ssl_verify=False,
        ))

    if os.path.isfile(TARGETS_FILE):
        import json
        with open(TARGETS_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f)
        seen_names = {t.name for t in targets}
        for entry in entries:
            name = (entry.get("name") or "").strip()
            if not name:
                print(f"WARNING: targets.json entry without a 'name' skipped: {entry}", file=sys.stderr)
                continue
            if name in seen_names:
                print(f"WARNING: duplicate target name '{name}' in targets.json skipped.", file=sys.stderr)
                continue
            host = (entry.get("host") or "").strip()
            entry_url = (entry.get("url") or "").strip()
            if host:
                entry_url = f"https://{host}:{entry.get('port', 443)}"
            if not entry_url:
                print(f"WARNING: target '{name}' has no host/url — skipped.", file=sys.stderr)
                continue
            targets.append(CPTarget(
                name=name, url=entry_url,
                domain=(entry.get("domain") or "SMC User").strip() or "SMC User",
                api_key=(entry.get("api_key") or "").strip() or None,
                username=(entry.get("username") or "").strip() or None,
                password=(entry.get("password") or "").strip() or None,
                ssl_verify=bool(entry.get("ssl_verify", False)),
            ))
            seen_names.add(name)

    return targets


def _build_client() -> CPClient | None:
    targets = _build_targets()
    return CPClient(targets) if targets else None


def _all_gateways(client: CPClient) -> tuple[list, list[str]]:
    """Gateway inventory across every configured management server. Returns
    (gateways, failed_target_names). A failed server's gateways are simply
    absent this run — callers that persist results should treat a non-empty
    failure list as 'inventory incomplete' and skip rewriting stored results,
    so one org's outage can't clobber another org's data."""
    gateways = []
    failed: list[str] = []
    for tname in client.target_names:
        try:
            gws = list_gateways(client, tname)
        except Exception as e:
            print(f"WARNING: could not reach management server '{tname}': {e}", file=sys.stderr)
            failed.append(tname)
            continue
        print(f"  [{tname}] {len(gws)} gateway(s): {', '.join(g.name for g in gws) or '(none)'}")
        gateways.extend(gws)
    return gateways, failed


def _keywords() -> list[str]:
    raw = os.getenv("ADVISORY_KEYWORDS", "check point,checkpoint,gaia")
    return [k.strip() for k in raw.split(",") if k.strip()]


def _nvd_cpe_vendors() -> list[str]:
    raw = os.getenv("NVD_CPE_VENDORS", "checkpoint")
    return [v.strip() for v in raw.split(",") if v.strip()]


def _cp_advisory_products() -> tuple[str, ...] | None:
    """Overrides cpadvisories.DEFAULT_RELEVANT_PRODUCTS when set -- which product
    lines from Check Point's advisory feed count as relevant to this tool's
    gateway/management inventory."""
    raw = os.getenv("CP_ADVISORY_PRODUCTS", "").strip()
    if not raw:
        return None
    return tuple(p.strip() for p in raw.split(",") if p.strip())


FIRST_RUN_LOOKBACK_DAYS = 90


def _gmail_creds() -> tuple[str, str] | None:
    address = os.getenv("GMAIL_ADDRESS", "").strip()
    app_password = os.getenv("GMAIL_APP_PASSWORD", "").strip()
    return (address, app_password) if address and app_password else None


def _nvd_cpe_lookup(cve_id: str) -> list[feeds.CpeRange]:
    """Lazy secondary source for matcher.match(): a cp_advisory-sourced Advisory
    carries no CPE data of its own, so when Check Point's own feed has no version
    row for a gateway yet, this gives the matcher an independent shot at resolving
    it via NVD's CPE ranges instead of settling for a context-free needs_review."""
    nvd_api_key = os.getenv("NVD_API_KEY", "").strip() or None
    detail = feeds.fetch_nvd_by_id(cve_id, api_key=nvd_api_key)
    return detail.cpe_ranges if detail else []


def _hotfix_check_enabled() -> bool:
    """ENABLE_HOTFIX_CHECK is off by default. When on, matcher.match() queries
    show-software-packages-per-targets to compare each gateway's installed Jumbo
    Hotfix Take against Check Point's own published fix guidance -- a read-only
    query against the management server; nothing executes on the gateway itself.
    See README's "Patch-level matching" section."""
    return os.getenv("ENABLE_HOTFIX_CHECK", "").strip().lower() in ("1", "true", "yes")


def _cp_advisory_to_advisory(fix: cpadvisories.AdvisoryFix) -> feeds.Advisory:
    """Converts a cpadvisories.AdvisoryFix (Check Point's own structured feed) into
    the same feeds.Advisory shape used everywhere else in the pipeline, carrying the
    structured product/Take rows through via cp_advisory_rows so matcher.py's
    top-priority path can use them."""
    return feeds.Advisory(
        cve_id=fix.cve_id,
        title=fix.cve_id,
        summary=fix.summary,
        source_url=fix.sk_url,
        source="cp_advisory",
        severity=fix.cp_severity,
        cvss=fix.cvss,
        published=fix.published,
        cp_advisory_rows=fix.rows,
        cp_severity=fix.cp_severity,
        sk_id=fix.sk_id,
    )


def cmd_check(dry_run: bool) -> None:
    client = _build_client()
    if not client:
        print("ERROR: No Check Point target configured. Set MANAGEMENT_HOST or S1C_URL in .env", file=sys.stderr)
        sys.exit(1)

    print("Fetching gateway inventory from Check Point management…")
    gateways, failed_targets = _all_gateways(client)
    print(f"  {len(gateways)} gateway(s) total across {len(client.target_names) - len(failed_targets)} "
          f"management server(s).")

    keywords = _keywords()
    state = store.load()

    if not failed_targets:
        # Lets the dashboard tell "polled and genuinely clean" apart from "never
        # heard of this gateway" -- both otherwise look like an empty matched list.
        # Skipped on a partial inventory so one server's outage can't make a real
        # gateway look newly-unknown.
        store.set_known_gateways(state, gateways)

    print("Fetching CISA KEV catalog…")
    kev_advisories = feeds.fetch_kev(keywords)
    print(f"  {len(kev_advisories)} matching entr(y/ies)")

    nvd_api_key = os.getenv("NVD_API_KEY", "").strip() or None
    since = store.get_last_checked(state, "nvd")
    if not since:
        # First run: don't pull the entire ~25-year CVE history for the vendor —
        # that's noise, not something to review today. Default to a recent window.
        since = (datetime.now(timezone.utc) - timedelta(days=FIRST_RUN_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000")
        print(f"First run — defaulting to the last {FIRST_RUN_LOOKBACK_DAYS} days instead of full CVE history.")
    print(f"Fetching NVD CVEs since {since}…")
    nvd_advisories = feeds.fetch_nvd(_nvd_cpe_vendors(), since=since, api_key=nvd_api_key)
    print(f"  {len(nvd_advisories)} matching entr(y/ies)")

    # Enrich KEV entries (which carry no CPE version data) with NVD detail where available.
    enriched_kev = []
    for adv in kev_advisories:
        detail = feeds.fetch_nvd_by_id(adv.cve_id, api_key=nvd_api_key) if adv.cve_id else None
        if detail:
            detail.kev = True
            detail.title = adv.title
            enriched_kev.append(detail)
        else:
            enriched_kev.append(adv)

    all_advisories = {a.cve_id: a for a in nvd_advisories}
    for a in enriched_kev:
        all_advisories[a.cve_id] = a  # KEV flag / detail takes precedence

    print("Fetching Check Point's own structured Security Advisories feed…")
    kev_cve_ids = {a.cve_id for a in kev_advisories}
    cp_fixes_all = cpadvisories.fetch_all()
    cp_since = store.get_last_checked(state, "cp_advisories")
    if not cp_since:
        # Same reasoning as the NVD first-run window: this feed has no server-side
        # "since" filter (fetch_all always returns the full active catalog), so on a
        # first run we'd otherwise treat all ~150 existing advisories as "new" and
        # draft/email every one of them at once. Filter to a recent window instead —
        # subsequent runs rely on seen_cve_ids for incremental behavior, not this.
        cp_since = (datetime.now(timezone.utc) - timedelta(days=FIRST_RUN_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000")
        print(f"First run for Check Point's advisory feed — filtering to the last {FIRST_RUN_LOOKBACK_DAYS} days.")
    cp_fixes_recent = [f for f in cp_fixes_all if (f.updated or f.published or "0") >= cp_since]
    print(f"  {len(cp_fixes_recent)} matching entr(y/ies)")
    for fix in cp_fixes_recent:
        cp_adv = _cp_advisory_to_advisory(fix)
        cp_adv.kev = fix.cve_id in kev_cve_ids
        all_advisories[fix.cve_id] = cp_adv  # Check Point's own structured data takes precedence

    new_advisories = [a for a in all_advisories.values() if not store.is_seen(state, a.cve_id)]

    # Refresh set: built from the FULL (unfiltered) Check Point feed, not just this
    # run's recent window. Gateway inventory can change independently of when Check
    # Point last updated an advisory (e.g. a gateway's reported version was wrong at
    # first-check time and corrected later) -- every already-seen CVE Check Point
    # still actively lists should be re-matched against the current gateways every
    # run, not only the ones that happen to fall in the flood-protection window.
    already_seen_advisories = []
    for fix in cp_fixes_all:
        if store.is_seen(state, fix.cve_id):
            cp_adv = _cp_advisory_to_advisory(fix)
            cp_adv.kev = fix.cve_id in kev_cve_ids
            already_seen_advisories.append(cp_adv)
    already_seen_cp_ids = {a.cve_id for a in already_seen_advisories}
    # Also cover already-seen NVD/KEV-only advisories (no Check Point feed entry) that
    # happen to still be in this run's NVD/KEV fetch -- same limited window as before.
    for a in all_advisories.values():
        if store.is_seen(state, a.cve_id) and a.cve_id not in already_seen_cp_ids:
            already_seen_advisories.append(a)

    print(f"{len(new_advisories)} new advisory(ies) to evaluate (of {len(all_advisories)} total fetched).")

    results = matcher.match(new_advisories, gateways, keywords,
                             client=client, target=TARGET_NAME, enable_hotfix_check=_hotfix_check_enabled(),
                             cp_relevant_products=_cp_advisory_products(), nvd_cpe_lookup=_nvd_cpe_lookup)
    _process_results(results, state, dry_run)

    # A CVE marked "seen" was matched against the gateway inventory *at the time it
    # was first processed*. If a gateway gets added/changed afterwards, that stale
    # match never gets revisited on its own -- the dashboard would keep showing "no
    # match" for a CVE that genuinely does apply to the new gateway. Re-run matching
    # for already-seen advisories still present in this run's fetch and refresh their
    # stored result, without re-drafting or re-emailing (they're already seen).
    if already_seen_advisories and failed_targets:
        # Re-matching with a partial inventory would rewrite stored results as if
        # the unreachable server's gateways no longer exist — every CVE matched to
        # them would silently lose those matches. Keep the existing stored results
        # until every configured server answers.
        print(f"Skipping the re-check of already-seen advisories: management server(s) "
              f"unreachable this run ({', '.join(failed_targets)}), inventory is incomplete.")
    elif already_seen_advisories:
        refreshed = matcher.match(already_seen_advisories, gateways, keywords,
                                   client=client, target=TARGET_NAME, enable_hotfix_check=_hotfix_check_enabled(),
                                   cp_relevant_products=_cp_advisory_products(), nvd_cpe_lookup=_nvd_cpe_lookup)
        newly_relevant = [r for r in refreshed if r.matched_gateways]
        tail = " (no new email sent, these are already seen)" if newly_relevant else ""
        print(f"Re-checked {len(refreshed)} already-seen advisory(ies) against the current gateway "
              f"inventory — {len(newly_relevant)} now match a gateway{tail}.")
        for r in newly_relevant:
            print(f"  {r.advisory.cve_id} now matches: {', '.join(g.name for g in r.matched_gateways)}")
        for r in refreshed:
            store.record_result(state, r)

    if dry_run:
        print("\n[DRY RUN] No state was changed — re-run without --dry-run to actually draft these.")
        return

    store.set_last_checked(state, "nvd")
    store.set_last_checked(state, "cp_advisories")
    store.save(state)


def cmd_add_advisory(source: str, dry_run: bool) -> None:
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            source = f.read()

    client = _build_client()
    gateways = _all_gateways(client)[0] if client else []
    keywords = _keywords()

    adv = feeds.fetch_manual(source)
    state = store.load()
    if store.is_seen(state, adv.cve_id):
        print(f"Already processed ({adv.cve_id}). Skipping.")
        return

    results = matcher.match([adv], gateways, keywords,
                             client=client, target=TARGET_NAME, enable_hotfix_check=_hotfix_check_enabled(),
                             cp_relevant_products=_cp_advisory_products())
    _process_results(results, state, dry_run)

    if dry_run:
        print("\n[DRY RUN] No state was changed — re-run without --dry-run to actually draft this.")
        return

    store.save(state)


def cmd_send_draft(cve_id: str, to_addrs: list[str] | None) -> None:
    """Sends the remediation email for an already-processed CVE. Rebuilds the exact same
    content as the draft (same fetch + match pipeline) rather than reading the draft back
    from Gmail, so it always reflects the current gateway inventory."""
    gmail_creds = _gmail_creds()
    if not gmail_creds:
        print("ERROR: GMAIL_ADDRESS/GMAIL_APP_PASSWORD not set in .env", file=sys.stderr)
        sys.exit(1)
    address, app_password = gmail_creds

    state = store.load()
    if not store.is_seen(state, cve_id):
        print(f"ERROR: {cve_id} hasn't been processed by 'check' or 'add-advisory' yet.", file=sys.stderr)
        sys.exit(1)

    nvd_api_key = os.getenv("NVD_API_KEY", "").strip() or None
    adv = feeds.fetch_nvd_by_id(cve_id, api_key=nvd_api_key)
    if not adv:
        print(f"ERROR: Could not re-fetch {cve_id} from NVD.", file=sys.stderr)
        sys.exit(1)
    adv.kev = any(k.cve_id == cve_id for k in feeds.fetch_kev(_keywords()))

    client = _build_client()
    gateways = _all_gateways(client)[0] if client else []
    results = matcher.match([adv], gateways, _keywords(),
                             client=client, target=TARGET_NAME, enable_hotfix_check=_hotfix_check_enabled(),
                             cp_relevant_products=_cp_advisory_products())
    if not results or results[0].resolved_not_applicable:
        print(f"ERROR: {cve_id} no longer matches any gateway/keyword — nothing to send.", file=sys.stderr)
        sys.exit(1)

    recipients = to_addrs or [address]
    drafter.send_email(results[0], address, app_password, recipients)
    print(f"Sent: {drafter.subject_for(results[0])} -> {', '.join(recipients)}")


def _process_results(results: list[matcher.MatchResult], state: dict, dry_run: bool) -> None:
    if not results:
        print("Nothing to draft.")
        return

    gmail_creds = _gmail_creds()
    for result in results:
        if result.resolved_not_applicable:
            # Confidently ruled out for every current gateway — record for dashboard
            # visibility, but there's nothing to draft or send an email about.
            store.mark_seen(state, result.advisory.cve_id)
            store.record_result(state, result)
            print(f"Resolved (not applicable to any gateway): {result.advisory.cve_id}")
            continue

        subject = drafter.subject_for(result)
        if dry_run:
            print(f"\n[DRY RUN] Would draft: {subject}")
            print(drafter.render_body(result))
        else:
            if not gmail_creds:
                print(f"ERROR: GMAIL_ADDRESS/GMAIL_APP_PASSWORD not set in .env — cannot draft '{subject}'.",
                      file=sys.stderr)
                continue
            address, app_password = gmail_creds
            drafter.create_gmail_draft(result, address, app_password)
            print(f"Drafted: {subject}")
        store.mark_seen(state, result.advisory.cve_id)
        store.record_result(state, result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Vendor advisory -> remediation draft workflow")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Poll feeds and draft remediation emails for new matches")
    p_check.add_argument("--dry-run", action="store_true", help="Print instead of creating Gmail drafts")

    p_add = sub.add_parser("add-advisory", help="Manually ingest a Check Point sk-article (URL, file, or pasted text)")
    p_add.add_argument("source", help="URL, file path, or raw advisory text")
    p_add.add_argument("--dry-run", action="store_true", help="Print instead of creating a Gmail draft")

    p_send = sub.add_parser("send-draft", help="Actually send the remediation email for an already-processed CVE")
    p_send.add_argument("cve_id", help="e.g. CVE-2024-24919")
    p_send.add_argument("--to", help="Comma-separated recipient list (default: your own GMAIL_ADDRESS)")

    args = parser.parse_args()
    if args.command == "check":
        cmd_check(args.dry_run)
    elif args.command == "add-advisory":
        cmd_add_advisory(args.source, args.dry_run)
    elif args.command == "send-draft":
        to_addrs = [a.strip() for a in args.to.split(",")] if args.to else None
        cmd_send_draft(args.cve_id, to_addrs)


if __name__ == "__main__":
    main()
