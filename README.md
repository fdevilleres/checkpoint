# advisory-watch

Watches for vendor security advisories affecting your Check Point gateways, matches them
against your actual gateway inventory (via the Management API), and saves a ready-to-review
remediation write-up as a **Gmail draft** — nothing is ever sent automatically.

## What's automated vs. manual

| Source | How | Automated? |
|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) | Public JSON feed, filtered by keyword | Yes |
| NVD (CVE + version-range data) | Public API, polled incrementally since last run | Yes |
| Check Point's own sk-article advisories | No public feed exists (SupportCenter requires login) | Manual: `python main.py add-advisory <url-or-text>` |

Matching is scoped to **Check Point products** (Gaia OS, gateway blades) — the Management API
gives us gateway name/version/OS/blades, not a general asset CMDB, so this tool can't tell you
whether a CVE in some unrelated product affects a server behind your firewall. It's built to
answer one question well: *"did a new CVE just drop against something in my Check Point estate,
and if so which gateways does it actually hit?"*

## Setup

1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and fill in:
   - Check Point Management API credentials (same vars as `posture-report`)
   - Optionally an `NVD_API_KEY` (raises the public API's rate limit)
   - `GMAIL_ADDRESS` + `GMAIL_APP_PASSWORD` (an [App Password](https://myaccount.google.com/apppasswords),
     not your real Gmail password) — used only to IMAP-append drafts into `[Gmail]/Drafts`

## Usage

```bash
# First run — always dry-run first to sanity check gateway inventory + feed matches
python main.py check --dry-run

# Create real Gmail drafts for anything new
python main.py check

# Manually ingest a Check Point sk-article advisory (URL, file path, or pasted text)
python main.py add-advisory "https://supportcenter.checkpoint.com/supportcenter/portal?...sk12345"
python main.py add-advisory --dry-run notes/sk12345.txt
```

State (which CVEs have already been drafted, last NVD poll time) lives in `state.json` next to
these scripts — delete it to reprocess everything from scratch. `--dry-run` never touches
`state.json` (or Gmail) at all, so running it repeatedly is always safe and won't cause a
subsequent real run to skip anything.

On a first run (no `state.json` yet), NVD is queried for CVEs *published* in the last 90 days —
not the vendor's entire ~25-year CVE history.

## Running it daily (Windows Task Scheduler)

1. Task Scheduler → Create Task
2. Trigger: Daily, at whatever time suits you
3. Action: `Start a program`
   - Program: `python`
   - Arguments: `main.py check`
   - Start in: this folder's full path
4. Optional: redirect output to a log file so you can spot-check runs
   (`Arguments: /c python main.py check >> check.log 2>&1`, Program: `cmd`)

## Design notes

- `cp_client.py` / gateway-listing logic is shared in spirit with `../posture-report` — same
  Management API session pattern, copied in so this tool stays a self-contained folder.
- Version matching (`matcher.py`) is intentionally pragmatic: it extracts numeric groups from
  version strings (handles Gaia's `R81.20` as well as NVD's plain `81.20`) rather than implementing
  full CPE semantics. Anything it can't confidently place is still surfaced as "needs manual
  review" instead of silently dropped.
- Drafts are created via IMAP `APPEND` with the `\Draft` flag — this only ever adds a draft to
  your own mailbox for you to review, edit, and send (or discard) yourself.
