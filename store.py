"""Tracks which CVE IDs have already been drafted, so repeated runs don't duplicate
Gmail drafts, plus the last-checked timestamp per feed for incremental NVD queries."""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "state.json")


def load(path: str = _DEFAULT_PATH) -> dict:
    if not os.path.exists(path):
        return {"seen_cve_ids": [], "last_checked": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save(state: dict, path: str = _DEFAULT_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def mark_seen(state: dict, cve_id: str) -> None:
    if cve_id not in state["seen_cve_ids"]:
        state["seen_cve_ids"].append(cve_id)


def is_seen(state: dict, cve_id: str) -> bool:
    return cve_id in state["seen_cve_ids"]


def set_last_checked(state: dict, feed: str) -> None:
    state["last_checked"][feed] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def get_last_checked(state: dict, feed: str) -> str | None:
    return state["last_checked"].get(feed)
