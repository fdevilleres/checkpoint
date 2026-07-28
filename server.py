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
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, send_from_directory

import store

EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "smartconsole-extension")

BIND_HOST = os.getenv("SERVER_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", "").strip() or BIND_HOST
PORT = int(os.getenv("SERVER_PORT", "5443").strip() or "5443")
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "").strip()
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", "").strip()

app = Flask(__name__)


@app.route("/<path:filename>")
def extension_static(filename):
    return send_from_directory(EXTENSION_DIR, filename)


@app.route("/api/gateway/<uid>/advisories")
def api_gateway_advisories(uid):
    state = store.load()
    return jsonify({
        "matched": store.results_for_gateway(state, uid),
        "unassigned": store.unassigned_results(state),
        "resolved": store.resolved_results(state),
    })


if __name__ == "__main__":
    if SSL_CERT_FILE and SSL_KEY_FILE:
        ssl_context = (SSL_CERT_FILE, SSL_KEY_FILE)
    else:
        ssl_context = "adhoc"  # self-signed — fine per Check Point's own docs, but expect a
                                # cert-trust prompt for anyone besides you on localhost

    print(f"Serving SmartConsole extension + API on https://{BIND_HOST}:{PORT}")
    print(f"Install in SmartConsole with manifest URL: https://{PUBLIC_HOST}:{PORT}/extension.json")
    if BIND_HOST != "127.0.0.1":
        print("NOTE: bound beyond localhost with no authentication — "
              "make sure only your intended audience can reach this host/port.")
    app.run(host=BIND_HOST, port=PORT, ssl_context=ssl_context, threaded=True)
