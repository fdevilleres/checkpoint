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
            lines.append(f"- **{gw.name}** — version {gw.version or 'unknown'}, blades: {blades}")
    elif result.needs_review:
        lines.append("- Could not be automatically matched to a gateway version — "
                      "verify manually against the inventory below the fold.")
    else:
        lines.append("- None matched.")
    lines.append("")

    lines.append("## Recommended action")
    if result.matched_gateways:
        lines.append("- Check the vendor advisory below for the fixed version / hotfix, "
                      "and schedule an upgrade or hotfix install on the affected gateways.")
    else:
        lines.append("- Confirm applicability against the affected gateways manually, "
                      "then proceed with the fix if relevant.")
    lines.append("")

    lines.append("## Source")
    lines.append(adv.source_url or "(manually provided)")
    if adv.source == "manual" and adv.raw_text and adv.raw_text != adv.summary:
        lines.append("")
        lines.append("## Raw advisory text")
        lines.append(adv.raw_text)

    return "\n".join(lines)


def subject_for(result: MatchResult) -> str:
    adv = result.advisory
    prefix = "[KEV] " if adv.kev else ""
    tag = " — needs manual review" if result.needs_review and not result.matched_gateways else ""
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
