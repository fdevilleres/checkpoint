# advisory-watch

Watches for vendor security advisories affecting your Check Point gateways, matches them
against your actual gateway inventory, and saves a ready-to-review remediation write-up as a
**Gmail draft** — nothing is ever sent automatically. Also ships a SmartConsole dashboard
extension so anyone with the gateway open can see the same matches without an email.

Gateway inventory can come from three places, all mergeable in the same deployment: your primary
Check Point Management Server (`.env`), any number of additional servers you hold credentials for
(`targets.json`, for other teams/orgs), and gateways that self-report their own version/Take with
no credentials at all (`gateway-report.sh`, for orgs you have no Management API access to). See
"Multiple management servers" and "Self-reported gateways" below.

## What's automated vs. manual

| Source | How | Automated? |
|---|---|---|
| Check Point's own structured Security Advisories feed | Public JSON API behind [support.checkpoint.com/security-advisories](https://support.checkpoint.com/security-advisories) — exact per-version Jumbo Hotfix Take cutoffs, no login, no scraping | Yes, always on — this is the primary source, see "Patch-level matching" below |
| CISA Known Exploited Vulnerabilities (KEV) | Public JSON feed, filtered by keyword | Yes — used to flag `[KEV]` (actively exploited) |
| NVD (CVE + version-range data) | Public API, polled incrementally since last run | Yes — fallback for anything not yet in Check Point's own feed |
| Check Point's own sk-article fix guidance (HTML scrape) | Only used when the structured feed has a "Details in SK" row with no parseable Take data | Best-effort fallback, when `ENABLE_HOTFIX_CHECK` is on |
| Browsing/discovering Check Point sk-articles generally | No public feed for browsing SupportCenter's search UI itself | Manual: `python main.py add-advisory <url-or-text>` |

Matching is scoped to **Check Point products** (Gaia OS, gateway blades) — the Management API
gives us gateway name/version/OS/blades, not a general asset CMDB, so this tool can't tell you
whether a CVE in some unrelated product affects a server behind your firewall. It's built to
answer one question well: *"did a new CVE just drop against something in my Check Point estate,
and if so which gateways does it actually hit?"*

## Patch-level matching (Check Point's own advisory feed → installed Jumbo Take)

`cpadvisories.py` fetches Check Point's own structured Security Advisories feed on every `check`
run — no opt-in needed, it's just a public JSON GET, same risk profile as the KEV/NVD fetches.
Per advisory it gives exact per-version data like *"R82.10: Take 158 or below is vulnerable"* —
far more precise than NVD's CPE version ranges, and unlike scraping individual sk articles
(`skfix.py`, now a fallback), it hasn't hit any bot-detection/rate-limiting in testing.

1. **Check Point's feed → vulnerability threshold**: for each gateway version in the advisory's
   product table, the feed gives the highest Take that is still *vulnerable* (e.g. *"Take 19 or
   below"*), or that the version is end-of-support with no Take that helps, or explicitly not
   affected at all.
1b. **sk-article Solution section → the Take that actually contains the fix.** These are two
   different numbers and the fix Take is **not** "threshold + 1": for CVE-2026-50751 on R82.10
   the threshold is Take 19, but the fix only shipped in Take 24 (Takes 20–23 don't carry it).
   `skfix.py` therefore reads the Take strictly from the article's *"Recommended step - Install
   Jumbo Hotfix Accumulator → The fix is included in these Jumbo Hotfix Accumulators"* table —
   deliberately ignoring the same article's vulnerable-configurations list, its "Hotfix on top"
   download table, and its revision history, all of which quote other Take numbers. Results are
   cached in `sk_cache.json` for a week, since Check Point's CDN bot-challenges repeated
   automated requests. If the article can't be read, the tool falls back to `threshold + 1` and
   **labels it as approximate** rather than presenting a Take that may not contain the fix.
2. **Gateway → installed Take** *(opt-in, see below)*: `hotfix.py` queries the Management API's
   `show-software-packages-per-targets` — a read-only lookup against the management server itself,
   nothing executes on the gateway — and parses the actually-installed JHF Take number.
3. **Compare**: installed Take below what's required → a confirmed patch gap (shown in the
   email/dashboard as e.g. *"Take 20 installed, Take 65 required — patch needed"*, with a direct
   link to Check Point's fix advisory). An end-of-support version gets a distinct "no Take fixes
   this — upgrade required" message instead of implying a hotfix will help.

**A gateway version not yet listed in an advisory's table is treated as "not yet assessed," not
"confirmed clean"** — Check Point actively extends these tables to newer versions over time
(confirmed live: rows exist for `R82`/`R82.10` on advisories that don't yet cover a newer `R82.20`
gateway). Only an explicit "not affected" entry resolves an advisory as not applicable.

**`ENABLE_HOTFIX_CHECK=true` in `.env` is off by default** — it gates step 2, the installed-Take
lookup, since that's the one thing in this tool that queries per-gateway state on your real
management server rather than public feed data. Everything else above (fetching the advisory feed, knowing
the required Take, flagging end-of-support versions) runs by default. With the feature off, a
known Take-based gap still shows up as "needs review" with the required Take number, rather than
being silently skipped — you just won't get the automatic yes/no against what's actually
installed. Installed Take is queried once per gateway per `check` run (cached), not once per
advisory. If a CVE isn't in Check Point's own feed yet, or a specific version has no structured
Take data ("Details in SK"), matching falls back to `skfix.py`'s sk-article scrape, then to the
NVD CPE-range heuristic — same fallback chain as before, just with a better primary source ahead
of it.

Set `CP_ADVISORY_PRODUCTS` in `.env` to override which Check Point product lines from the
advisory feed are considered relevant to your gateway/management inventory (default covers
Security Gateways, Security Management, ClusterXL, VSX, CloudGuard Network, and common blades —
excludes desktop-only products like SmartConsole and Harmony Endpoint).

## Setup

1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and fill in:
   - Check Point Management API credentials (same vars as `posture-report`)
   - Optionally an `NVD_API_KEY` (raises the public API's rate limit)
   - `GMAIL_ADDRESS` + `GMAIL_APP_PASSWORD` (an [App Password](https://myaccount.google.com/apppasswords),
     not your real Gmail password) — used only to IMAP-append drafts into `[Gmail]/Drafts`

### Multiple management servers (multi-org)

The `.env` server is the primary. To poll additional Check Point Management Servers in the same
run — e.g. one per team or partner org, each with its own credentials — copy
`targets.json.example` to `targets.json` (gitignored, since it holds credentials) and add one
entry per extra server. Each entry needs a unique `name`, a `host`+`port` (or a full `url` for
Smart-1 Cloud), and either an `api_key` or `username`+`password`.

`check` then merges every server's gateways into one inventory: matching, the opt-in
installed-Take lookup, and the dashboard all work per-gateway against the server that owns it.
If any configured server is unreachable during a run, its gateways are skipped for that run and
the re-check of already-seen advisories is deferred (so an outage at one org can't silently
erase another org's stored matches).

This still means the advisory-watch operator holds credentials to every server in `targets.json`
— a real ask for an external org. If that's not workable, see "Self-reported gateways" below for
a credential-free alternative.

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

## SmartConsole dashboard extension

`main.py check` also now records full match results (not just seen/unseen) into `state.json`,
keyed by CVE ID with which gateway UIDs they matched. `server.py` serves that data as a small
read-only local API, plus a real Check Point **SmartConsole Extension** (`smartconsole-extension/`)
that adds an "Advisories" tab under each gateway's properties, showing exactly what's already
matched to it — no email needed to see it.

```bash
python server.py
# Serving SmartConsole extension + API on https://127.0.0.1:5443
```

Then in SmartConsole: **Global Properties → Extensions** (or the extensions manager for your
version — see the [SmartConsole Extension Developer Guide](https://sc1.checkpoint.com/documents/SmartConsole/Extensions/index.html))
→ install by pasting the manifest URL: `https://127.0.0.1:5443/extension.json`. Select any
gateway and open its new **Advisories** tab. Confirmed working in a real SmartConsole client —
three sections: advisories matched to that gateway, advisories flagged for manual review that
couldn't be pinned to a specific gateway, and a collapsed "Resolved" section for advisories that
were checked and confirmed not applicable (so "checked, doesn't apply" stays visibly distinct
from "never checked").

Notes:
- `server.py` needs to be running (as a standing background process) whenever you want the tab
  to load — it's separate from the weekly `check` Task Scheduler job. Run manually with
  `python server.py`, or wire `run_server.bat` into Task Scheduler with an "At startup" trigger
  (no end time) so it survives reboots — see "Deploying this for a team" below.
- The extension itself only ever does `GET`s — it reads `state.json` (or a live self-reported
  match, see below) through the local API, never talks to Gmail or the Management API, and
  requests no special SmartConsole permissions (verified against the official docs and the
  `show-gateways-interfaces` reference example in
  [CheckPointSW/smart-console-extensions](https://github.com/CheckPointSW/smart-console-extensions)).
  The one write path on the server is `/api/report`, used by `gateway-report.sh`, not the
  extension — see "Self-reported gateways" below.
- Uses a self-signed HTTPS cert (`ssl_context='adhoc'`) by default — explicitly allowed per the
  docs. Set `SSL_CERT_FILE`/`SSL_KEY_FILE` in `.env` to use a real cert instead (see below).

## Self-reported gateways (no Management API access needed)

`targets.json` (above) requires the advisory-watch operator to hold credentials to every polled
management server — a real ask for an external org. `gateway-report.sh` is the credential-free
alternative: an admin on the *other* org's side runs it from their **own** SmartConsole's Scripts
Repository against their gateway object (or their SMS). It executes on the gateway using their
already-authenticated SmartConsole session — no credentials ever change hands with the
advisory-watch operator. The script reads `fw ver` + the installed JHF Take from `cpinfo`
locally and POSTs just `{name, version, take}` to this server's `/api/report`.

Setup on their side:
1. In SmartConsole: **Manage & Settings → Blades → Scripts Repository** (or the equivalent for
   your version) → add `gateway-report.sh` as a new script.
2. Run it against the gateway object, passing this server's URL and (if the object name differs
   from the gateway's Gaia hostname) the object name: `gateway-report.sh https://your-server:5443 GW-NAME`.
3. Open that gateway's **Advisories** tab as normal — the extension already sends the selected
   object's name, so the dashboard automatically falls back to the self-reported version/Take the
   moment no polled match exists for that UID, with no extra configuration needed.

### Why the tab doesn't just detect this itself

It partially does. The extension requests `details-level: full` and the `get-read-only-session`
permission, so it always has the gateway's **version** for free — no network call, straight off the
`get-context` response. It also *attempts* to read the installed **Take** the same way, by calling
`show-software-packages-per-targets` directly against the tester's own management server, using the
read-only session SmartConsole grants their login.

Confirmed live against a real, correctly-configured SmartConsole session (permission approved,
context populated with a valid `sid`/version): that direct Take fetch fails with `Failed to fetch`.
Browsers collapse two distinct failures into that one generic message, and either is plausible here
and outside this tool's control: the Management API very likely doesn't send CORS headers permitting
a cross-origin request from this extension's origin, and/or the tester's management server uses a
self-signed certificate a browser `fetch()` has no way to trust (the `certificate-fingerprint` data
SmartConsole provides isn't a browser-usable trust-pinning mechanism). This is left in as a
best-effort attempt — it fails fast and falls back safely, and may work in an environment with a
CA-trusted certificate — but `gateway-report.sh` remains the reliable path for the installed Take on
a foreign management server. Failures are visible in `client_diagnostics.log` via `/api/client-log`
if you want to confirm which failure mode a given tester hit.

This path matches live at request time (not persisted into the shared `state.json`) against the
same Check Point advisory feed + NVD fallback the polled path uses, so results are consistent
between the two — just recomputed fresh each time rather than cached. Reports live in
`reported.json`, gitignored, separate from `state.json` so a `check` sync never overwrites them.

**Same no-authentication caveat as the rest of this dashboard** — `/api/report` accepts a report
for any name from anyone who can reach the server. Fine for a trusted test group; add
authentication before wider exposure.

## Deploying this for a team

By default `server.py` only listens on `127.0.0.1` — nobody but you can reach it. To let
colleagues install the same "Advisories" tab in their own SmartConsole, run it on a real host
instead of your own machine:

1. Clone/copy this folder onto an internal server or VM you control, and set it up like normal
   (`pip install -r requirements.txt`, your own `.env` with your Check Point + Gmail creds).
2. In `.env`, set:
   ```
   SERVER_BIND_HOST=0.0.0.0
   SERVER_PUBLIC_HOST=<this host's real reachable hostname or IP>
   ```
3. Run `python server.py` (or `run_server.bat`) — it prints the install URL using
   `SERVER_PUBLIC_HOST`, e.g. `https://advisorywatch.internal.example.com:5443/extension.json`.
4. Give that URL to colleagues. That's it on their end — no Python, no `.env`, no local checkout.
   They just paste the URL into their own SmartConsole's extension installer.

**Security — read this before exposing beyond your own machine**: there is no authentication on
the API. Anyone who can reach the configured host/port can see your gateway inventory and CVE
match data. Restrict reachability with a firewall or VPN-only network, and never expose this to
the public internet. If your org has an internal CA, set `SSL_CERT_FILE`/`SSL_KEY_FILE` in `.env`
so colleagues don't hit a self-signed cert warning when their SmartConsole loads the extension.

**Keeping it running** so it survives reboots:
- Windows: Task Scheduler → Create Task → Trigger: "At startup" (no end time) → Action: run
  `run_server.bat`, "Start in" this folder.
- Linux: a minimal systemd unit —
  ```ini
  [Unit]
  Description=advisory-watch SmartConsole extension server
  After=network.target

  [Service]
  WorkingDirectory=/opt/advisory-watch
  ExecStart=/usr/bin/python3 server.py
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target
  ```

If you're redistributing your own deployment further, `smartconsole-extension/extension.json`'s
`product-url` and `provider` fields are just display metadata shown during install — update them
to your own, though nothing breaks if you leave them as-is.

## Design notes

- `cp_client.py` / gateway-listing logic is shared in spirit with `../posture-report` — same
  Management API session pattern, copied in so this tool stays a self-contained folder.
- Version matching (`matcher.py`) is intentionally pragmatic: it extracts numeric groups from
  version strings (handles Gaia's `R81.20` as well as NVD's plain `81.20`) rather than implementing
  full CPE semantics. Anything it can't confidently place is still surfaced as "needs manual
  review" instead of silently dropped.
- Drafts are created via IMAP `APPEND` with the `\Draft` flag — this only ever adds a draft to
  your own mailbox for you to review, edit, and send (or discard) yourself.
