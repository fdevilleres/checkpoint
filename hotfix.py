"""Runs a bounded, read-only diagnostic on a real gateway/management server via the
Check Point Management API's run-script command, to determine its actually-installed
Jumbo Hotfix Accumulator (JHF) Take number.

This is the one part of advisory-watch that executes something on production
infrastructure rather than just reading metadata -- gated behind ENABLE_HOTFIX_CHECK
in .env (default off). Confirmed live against a real gateway: correctly reports
Take 20 for a box running "HOTFIX_R82_20_T313_EA_JHF_MAIN Take: 20"."""

from __future__ import annotations
import base64
import re
import time

from cp_client import CPClient

# Bounded and read-only: times out after 25s, and the line cap is generous enough to
# comfortably include the [FW1]/[MGMT] sections even on a heavily hotfixed box.
_SCRIPT = """
echo "=== fw ver ==="
fw ver 2>&1
echo "=== installed hotfixes (bounded cpinfo scan) ==="
timeout 25 cpinfo -y all 2>&1 | head -150
"""

_SECTION_RE = re.compile(r"^\[(\w+)\]\s*$")
_JHF_TAKE_RE = re.compile(r"JHF_MAIN\s+Take:\s*(\d+)", re.IGNORECASE)
_NO_HOTFIXES_RE = re.compile(r"no hotfixes\.\.", re.IGNORECASE)

# Prefer the firewall module's own section (relevant to gateway CVEs); fall back to
# MGMT for a pure management server, which has no FW1 blade of its own.
_PREFERRED_SECTIONS = ("FW1", "MGMT")


def get_installed_jhf_take(client: CPClient, target: str, gateway_name: str, poll_timeout: float = 30.0) -> int | None:
    """Returns the installed JHF Take number (0 if that section explicitly shows "no
    hotfixes"), or None if the script/task didn't complete or its output couldn't be
    confidently parsed. Never raises -- callers should treat None as "couldn't
    determine, fall back to manual review", not as an error."""
    try:
        resp = client.call("run-script", target, {
            "script-name": "advisory-watch-jhf-check",
            "script": _SCRIPT,
            "targets": [gateway_name],
        })
        task_id = resp["tasks"][0]["task-id"]
    except Exception:
        return None

    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        try:
            task_resp = client.call("show-task", target, {"task-id": task_id, "details-level": "full"})
            task = task_resp["tasks"][0]
        except Exception:
            return None
        status = task.get("status")
        if status == "succeeded":
            details = task.get("task-details", [])
            if not details:
                return None
            b64 = details[0].get("responseMessage", "")
            try:
                output = base64.b64decode(b64).decode("utf-8", errors="replace")
            except Exception:
                return None
            return _parse_jhf_take(output)
        if status in ("failed", "partially succeeded"):
            return None
        time.sleep(2)
    return None  # timed out


def _parse_jhf_take(output: str) -> int | None:
    """Section-aware: only trusts a "no hotfixes" verdict when it's scoped to the
    FW1/MGMT section specifically, since cpinfo's output legitimately says "No
    hotfixes.." for many unrelated subsystems even on a fully patched gateway --
    treating any such line anywhere in the output as "unpatched" would be wrong."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        m = _SECTION_RE.match(line.strip())
        if m:
            current = m.group(1).upper()
            sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)

    for section_name in _PREFERRED_SECTIONS:
        lines = sections.get(section_name)
        if not lines:
            continue
        block = "\n".join(lines)
        take_match = _JHF_TAKE_RE.search(block)
        if take_match:
            return int(take_match.group(1))
        if _NO_HOTFIXES_RE.search(block):
            return 0
    return None
