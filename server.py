"""Local HTTPS host for the SmartConsole extension: serves the extension bundle
(smartconsole-extension/) as static files, plus a small JSON API the extension's
JS reads from. Read-only — this process never talks to Gmail or the CP Management
API itself; it only reads what `main.py check` already recorded in state.json.

Run with: python server.py
Then install the extension in SmartConsole by pasting the printed manifest URL.

By default this only listens on 127.0.0.1 (your own machine). To let colleagues
install the extension too, set SERVER_BIND_HOST=0.0.0.0 and SERVER_PUBLIC_HOST to
this machine's real reachable address in .env — see .env.example and the
"Deploying this for a team" section in README.md. There is no authentication:
anyone who can reach the configured host/port sees your gateway inventory and
CVE data, so only do this on a network you trust.
"""

from __future__ import annotations
import os
import ssl
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.serving import WSGIRequestHandler, generate_adhoc_ssl_context

import reported
import store

EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "smartconsole-extension")
CLIENT_LOG_PATH = os.path.join(os.path.dirname(__file__), "client_diagnostics.log")

BIND_HOST = os.getenv("SERVER_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", "").strip() or BIND_HOST
PORT = int(os.getenv("SERVER_PORT", "5443").strip() or "5443")
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "").strip()
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", "").strip()
# Werkzeug's dev-server access log otherwise prints an unlabeled server-local
# timestamp -- on a UTC-configured host (the common case for a cloud VM) that
# silently reads as "wrong" to anyone checking it against their own wall clock.
# Always show UTC explicitly, plus a named zone for convenience if one is set.
LOG_TIMEZONE = os.getenv("LOG_TIMEZONE", "America/New_York").strip()

app = Flask(__name__)


class _TimestampedRequestHandler(WSGIRequestHandler):
    """Access-log timestamps labelled with an explicit zone, since an
    unlabelled one is only unambiguous if you already know the server's own
    timezone -- which a remote reader usually doesn't."""

    def log_date_time_string(self) -> str:
        now = datetime.now(timezone.utc)
        stamp = now.strftime("%d/%b/%Y %H:%M:%S UTC")
        if LOG_TIMEZONE:
            try:
                from zoneinfo import ZoneInfo
                local = now.astimezone(ZoneInfo(LOG_TIMEZONE))
                stamp += local.strftime(" (%H:%M:%S %Z)")
            except Exception:
                pass  # unknown/misconfigured LOG_TIMEZONE -- UTC alone still printed
        return stamp


@app.route("/<path:filename>")
def extension_static(filename):
    return send_from_directory(EXTENSION_DIR, filename)


@app.route("/api/gateway/<uid>/advisories")
def api_gateway_advisories(uid):
    state = store.load()
    matched = store.results_for_gateway(state, uid)
    name = (request.args.get("name") or "").strip()

    # Gateway unknown to the polled inventory (no stored matches) but the
    # extension told us its name and that name has self-reported via the
    # SmartConsole script-repository flow -> serve a live match against the
    # reported version/Take instead of an empty page.
    if not matched and name:
        report_payload = reported.advisories_for(name, uid)
        if report_payload is not None:
            report_payload.setdefault("unknown", False)
            return jsonify(report_payload)

    # Neither a polled result nor a self-report exists for this gateway. An
    # empty "matched" here would be indistinguishable from a gateway that was
    # actually checked and found clean -- confirmed live: two real testers on
    # different, never-reported gateways got byte-for-byte identical responses.
    # "unknown" tells the extension to say so plainly instead of implying "clean".
    known = store.is_known_gateway(state, uid)
    return jsonify({
        "matched": matched,
        "unassigned": store.unassigned_results(state),
        "resolved": store.resolved_results(state),
        "unknown": not known and not matched,
    })


@app.route("/api/client-log", methods=["POST"])
def api_client_log():
    """Best-effort diagnostic channel for advisories.js's auto-detection path
    (tryAutoDetect). Lets us see WHY it failed on a tester's machine -- no
    "management-server-api" in context at all (permission never granted) vs. the
    context being present but the direct fetch() itself failing (most likely a
    certificate the browser doesn't trust on their management server) --
    without needing console access on their side. Purely observational: never
    read by matching or persisted anywhere matching logic touches."""
    data = request.get_json(force=True, silent=True) or {}
    line = "{} | name={} | stage={} | detail={}".format(
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        data.get("name"), data.get("stage"), data.get("detail"),
    )
    try:
        with open(CLIENT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    return jsonify({"ok": True})


@app.route("/api/report", methods=["POST"])
def api_report():
    """Self-report endpoint for gateway-report.sh (SmartConsole script repository).
    Body: {"name": "...", "version": "R82.10", "take": 24 | null}. As
    unauthenticated as the rest of this dashboard -- see reported.py's trust note."""
    data = request.get_json(force=True, silent=True) or {}
    ok, message = reported.save_report(data.get("name"), data.get("version"), data.get("take"))
    status = 200 if ok else 400
    return jsonify({"ok": ok, "message": message}), status


if __name__ == "__main__":
    if SSL_CERT_FILE and SSL_KEY_FILE:
        ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE)
    else:
        # Self-signed, same cert Werkzeug's "adhoc" shorthand would generate -- but
        # built explicitly so the TLS version range can be pinned. Confirmed live: a
        # Check Point gateway's embedded curl_cli/OpenSSL build (used by
        # gateway-report.sh, run ON the gateway) fails outbound TLS 1.3 against the
        # default adhoc context with SSL_ERROR_SYSCALL mid-handshake -- TCP connects,
        # ClientHello goes out, then the connection just drops, no clean TLS alert.
        # Forcing --tlsv1.2 on the client fixed it immediately, so capping both min
        # and max to TLS 1.2 here avoids the whole class of "some client's TLS 1.3
        # stack doesn't interop with ours" for every future gateway/tester, at no
        # real cost given this is already an unauthenticated internal tool.
        ssl_context = generate_adhoc_ssl_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        # expect a cert-trust prompt for anyone besides you on localhost either way

    print(f"Serving SmartConsole extension + API on https://{BIND_HOST}:{PORT}")
    print(f"Install in SmartConsole with manifest URL: https://{PUBLIC_HOST}:{PORT}/extension.json")
    if BIND_HOST != "127.0.0.1":
        print("NOTE: bound beyond localhost with no authentication — "
              "make sure only your intended audience can reach this host/port.")
    app.run(host=BIND_HOST, port=PORT, ssl_context=ssl_context, threaded=True,
            request_handler=_TimestampedRequestHandler)
