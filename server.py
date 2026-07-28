"""Local HTTPS host for the SmartConsole extension: serves the extension bundle
(smartconsole-extension/) as static files, plus a small JSON API the extension's
JS reads from. Read-only — this process never talks to Gmail or the CP Management
API itself; it only reads what `main.py check` already recorded in state.json.

Run with: python server.py
Then install the extension in SmartConsole by pasting: https://127.0.0.1:5443/extension.json
"""

from __future__ import annotations
import os
from flask import Flask, jsonify, send_from_directory

import store

EXTENSION_DIR = os.path.join(os.path.dirname(__file__), "smartconsole-extension")
PORT = 5443

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
    print(f"Serving SmartConsole extension + API on https://127.0.0.1:{PORT}")
    print(f"Install in SmartConsole with manifest URL: https://127.0.0.1:{PORT}/extension.json")
    app.run(host="127.0.0.1", port=PORT, ssl_context="adhoc", threaded=True)
