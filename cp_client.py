"""Check Point Management API client — mirrors the session logic in the Node.js MCP server."""

import json
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CPTarget:
    name: str
    url: str
    domain: str
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    ssl_verify: bool = False


@dataclass
class _Session:
    sid: str
    created_at: float = field(default_factory=time.time)
    TTL = 500

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) >= self.TTL


class CPClient:
    def __init__(self, targets: list[CPTarget]):
        self._targets: dict[str, CPTarget] = {t.name: t for t in targets}
        self._sessions: dict[str, _Session] = {}

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------
    def _post(self, base_url: str, path: str, payload: dict, headers: dict = {}, ssl_verify: bool = False) -> dict:
        url = f"{base_url}/web_api/{path}"
        data = json.dumps(payload).encode()
        ctx = ssl.create_default_context() if ssl_verify else ssl._create_unverified_context()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            return json.loads(resp.read())

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    def _login(self, name: str) -> _Session:
        tgt = self._targets[name]
        payload: dict = {"domain": tgt.domain}
        if tgt.api_key:
            payload["api-key"] = tgt.api_key
        elif tgt.username and tgt.password:
            payload["user"] = tgt.username
            payload["password"] = tgt.password
        else:
            raise ValueError(f"Target '{name}' has no credentials configured.")
        resp = self._post(tgt.url, "login", payload, ssl_verify=tgt.ssl_verify)
        if "sid" not in resp:
            raise RuntimeError(f"Login to '{name}' failed: {resp}")
        return _Session(sid=resp["sid"])

    def _get_sid(self, name: str) -> str:
        sess = self._sessions.get(name)
        if sess and not sess.expired:
            return sess.sid
        sess = self._login(name)
        self._sessions[name] = sess
        return sess.sid

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def call(self, command: str, target: str, payload: dict = {}) -> dict:
        if target not in self._targets:
            raise KeyError(f"Unknown target '{target}'. Available: {list(self._targets)}")
        for attempt in range(2):
            sid = self._get_sid(target)
            tgt = self._targets[target]
            try:
                return self._post(tgt.url, command, payload, {"X-chkp-sid": sid}, tgt.ssl_verify)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403) and attempt == 0:
                    del self._sessions[target]
                    continue
                body = e.read().decode()
                raise RuntimeError(f"CP API {e.code} on '{command}': {body}") from e
        raise RuntimeError(f"Failed '{command}' on '{target}' after retry.")

    def paginate(self, command: str, target: str, payload: dict = {}, key: str = "objects") -> list:
        """Fetch all pages of a listing command."""
        results = []
        offset = 0
        limit = 200
        total = None
        while total is None or offset < total:
            page = self.call(command, target, {**payload, "limit": limit, "offset": offset, "details-level": "standard"})
            total = page.get("total", 0)
            results.extend(page.get(key, []))
            offset += limit
            if offset >= total:
                break
        return results

    def logout(self, target: str):
        sess = self._sessions.pop(target, None)
        if sess:
            tgt = self._targets[target]
            try:
                self._post(tgt.url, "logout", {}, {"X-chkp-sid": sess.sid}, tgt.ssl_verify)
            except Exception:
                pass

    def logout_all(self):
        for name in list(self._sessions):
            self.logout(name)

    @property
    def target_names(self) -> list[str]:
        return list(self._targets)
