"""Renders a remediation write-up for a matched advisory and saves it as a Gmail
draft (IMAP APPEND to [Gmail]/Drafts) — never sends anything."""

from __future__ import annotations
import imaplib
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText

from matcher import MatchResult


def render_body(result: MatchResult) -> str:
    adv = result.advisory
    lines = []
    lines.append(f"# Remediation Advisory: {adv.cve_id or 'Unassigned'}")
    lines.append("")
    if adv.kev:
        lines.append("**⚠ CISA Known Exploited Vulnerability — treat as high priority.**")
    if adv.cvss is not None:
        lines.append(f"**CVSS:** {adv.cvss} ({adv.severity})")
    if adv.published:
        lines.append(f"**Published:** {adv.published}")
    lines.append("")
    lines.append("## Summary")
    lines.append(adv.summary or adv.raw_text or "(no summary available)")
    lines.append("")

    lines.append("## Affected gateways")
    if result.matched_gateways:
        for gw in result.matched_gateways:
            blades = ", ".join(gw.blades) if gw.blades else "none listed"
            gap = result.gateway_take_gap.get(gw.uid)
            required_only = result.gateway_required_take.get(gw.uid)
            take_source = result.gateway_take_source.get(gw.uid)
            # "latest" means the number is Check Point's own latest available Take
            # for this version, not just whatever Take happens to fix this one CVE.
            is_latest = take_source == "latest"
            # "inferred" means we only had the vulnerability threshold, so the number
            # is a lower bound, not the published fix Take -- never state it flatly.
            inferred = take_source == "inferred"
            caveat = (" — this is the lowest Take above the vulnerable range, not a "
                       "confirmed fix Take; check the advisory below for the exact "
                       "Jumbo Hotfix Accumulator that carries the fix") if inferred else ""
            action = "update to the latest Jumbo Hotfix Accumulator" if is_latest else "install Jumbo Hotfix Accumulator"
            if gw.uid in result.eos_gateway_uids:
                lines.append(f"- **{gw.name}** — version {gw.version or 'unknown'}: "
                              f"end-of-support version, no Jumbo Hotfix fixes this — upgrade required")
            elif gap:
                installed, required = gap
                lines.append(f"- **{gw.name}** — version {gw.version or 'unknown'}: "
                              f"{action} Take {required} or above "
                              f"(currently installed: Take {installed}){caveat}")
            elif required_only is not None:
                lines.append(f"- **{gw.name}** — version {gw.version or 'unknown'}: "
                              f"{action} Take {required_only} or above — "
                              f"installed Take couldn't be confirmed automatically "
                              f"(enable ENABLE_HOTFIX_CHECK to confirm){caveat}")
            else:
                lines.append(f"- **{gw.name}** — version {gw.version or 'unknown'}, blades: {blades}")
    elif result.needs_review:
        lines.append("- Could not be automatically matched to a gateway version — "
                      "verify manually against the inventory below the fold.")
    else:
        lines.append("- None matched.")
    lines.append("")

    lines.append("## Recommended action")
    if result.eos_gateway_uids:
        lines.append("- These gateways are on an end-of-support version with no available Jumbo "
                      "Hotfix fix — plan an upgrade to a supported version.")
    elif result.gateway_take_gap:
        lines.append("- Install the required Jumbo Hotfix Accumulator Take (see Check Point's "
                      "fix advisory below) on the affected gateways.")
    elif result.gateway_required_take:
        lines.append("- The required Jumbo Hotfix Accumulator Take is known for these gateways, but "
                      "the installed Take couldn't be confirmed automatically — check manually, or "
                      "enable ENABLE_HOTFIX_CHECK in .env so this is verified for you next time.")
    elif result.matched_gateways:
        lines.append("- Check the vendor advisory below for the fixed version / hotfix, "
                      "and schedule an upgrade or hotfix install on the affected gateways.")
    else:
        lines.append("- Confirm applicability against the affected gateways manually, "
                      "then proceed with the fix if relevant.")
    lines.append("")

    lines.append("## Source")
    lines.append(adv.source_url or "(manually provided)")
    if result.sk_url:
        lines.append(f"Check Point fix advisory: {result.sk_url}")
    if adv.source == "manual" and adv.raw_text and adv.raw_text != adv.summary:
        lines.append("")
        lines.append("## Raw advisory text")
        lines.append(adv.raw_text)

    return "\n".join(lines)


def subject_for(result: MatchResult) -> str:
    adv = result.advisory
    prefix = "[KEV] " if adv.kev else ""
    tag = " — needs manual review" if result.needs_review else ""
    return f"{prefix}Remediation: {adv.cve_id or adv.title[:60]}{tag}"


def create_gmail_draft(result: MatchResult, gmail_address: str, gmail_app_password: str) -> None:
    """Appends a draft message to the account's [Gmail]/Drafts folder. Nothing is sent."""
    body = render_body(result)
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject_for(result)
    msg["From"] = gmail_address
    msg["To"] = gmail_address  # placeholder recipient; user edits before sending

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    try:
        imap.login(gmail_address, gmail_app_password)
        imap.append(
            '"[Gmail]/Drafts"',
            r"(\Draft)",
            imaplib.Time2Internaldate(time.time()),
            msg.as_bytes(),
        )
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def send_email(result: MatchResult, gmail_address: str, gmail_app_password: str, to_addrs: list[str]) -> None:
    """Actually sends the remediation write-up via SMTP. Unlike create_gmail_draft, this
    is a real send — only call it after the user has explicitly asked, per advisory."""
    msg = MIMEText(render_body(result), "plain")
    msg["Subject"] = subject_for(result)
    msg["From"] = gmail_address
    msg["To"] = ", ".join(to_addrs)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.login(gmail_address, gmail_app_password)
        server.sendmail(gmail_address, to_addrs, msg.as_string())
