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
import feeds
import matcher
import drafter
import store

TARGET_NAME = "management"


def _build_client() -> CPClient | None:
    mgmt_host = os.getenv("MANAGEMENT_HOST", "").strip()
    s1c_url = os.getenv("S1C_URL", "").strip()
    domain = os.getenv("DOMAIN", "SMC User").strip() or "SMC User"
    api_key = os.getenv("API_KEY", "").strip() or None
    username = os.getenv("USERNAME", "").strip() or None
    password = os.getenv("PASSWORD", "").strip() or None

    if mgmt_host:
        url = f"https://{mgmt_host}:{os.getenv('MANAGEMENT_PORT', '443').strip()}"
    elif s1c_url:
        url = s1c_url
    else:
        return None

    target = CPTarget(name=TARGET_NAME, url=url, domain=domain,
                       api_key=api_key, username=username, password=password, ssl_verify=False)
    return CPClient([target])


def _keywords() -> list[str]:
    raw = os.getenv("ADVISORY_KEYWORDS", "check point,checkpoint,gaia")
    return [k.strip() for k in raw.split(",") if k.strip()]


def _nvd_cpe_vendors() -> list[str]:
    raw = os.getenv("NVD_CPE_VENDORS", "checkpoint")
    return [v.strip() for v in raw.split(",") if v.strip()]


FIRST_RUN_LOOKBACK_DAYS = 90


def _gmail_creds() -> tuple[str, str] | None:
    address = os.getenv("GMAIL_ADDRESS", "").strip()
    app_password = os.getenv("GMAIL_APP_PASSWORD", "").strip()
    return (address, app_password) if address and app_password else None


def cmd_check(dry_run: bool) -> None:
    client = _build_client()
    if not client:
        print("ERROR: No Check Point target configured. Set MANAGEMENT_HOST or S1C_URL in .env", file=sys.stderr)
        sys.exit(1)

    print("Fetching gateway inventory from Check Point management…")
    gateways = list_gateways(client, TARGET_NAME)
    print(f"  {len(gateways)} gateway(s) found: {', '.join(g.name for g in gateways) or '(none)'}")

    keywords = _keywords()
    state = store.load()

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

    new_advisories = [a for a in all_advisories.values() if not store.is_seen(state, a.cve_id)]
    print(f"{len(new_advisories)} new advisory(ies) to evaluate (of {len(all_advisories)} total fetched).")

    results = matcher.match(new_advisories, gateways, keywords)
    _process_results(results, state, dry_run)

    if dry_run:
        print("\n[DRY RUN] No state was changed — re-run without --dry-run to actually draft these.")
        return

    store.set_last_checked(state, "nvd")
    store.save(state)


def cmd_add_advisory(source: str, dry_run: bool) -> None:
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            source = f.read()

    client = _build_client()
    gateways = list_gateways(client, TARGET_NAME) if client else []
    keywords = _keywords()

    adv = feeds.fetch_manual(source)
    state = store.load()
    if store.is_seen(state, adv.cve_id):
        print(f"Already processed ({adv.cve_id}). Skipping.")
        return

    results = matcher.match([adv], gateways, keywords)
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
    gateways = list_gateways(client, TARGET_NAME) if client else []
    results = matcher.match([adv], gateways, _keywords())
    if not results:
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
