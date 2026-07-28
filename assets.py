"""Pulls the gateway inventory (name, version, OS, blades) from Check Point management."""

from __future__ import annotations
from dataclasses import dataclass, field
from cp_client import CPClient

BLADE_KEYS = ("firewall", "ips", "application-control", "url-filtering",
              "content-awareness", "threat-emulation", "anti-virus",
              "anti-bot", "vpn", "mobile-access")


@dataclass
class Gateway:
    name: str
    uid: str
    type: str
    version: str = ""
    os_name: str = ""
    blades: list[str] = field(default_factory=list)


def _fetch_full_gateways(client: CPClient, target: str) -> list[dict]:
    """Pages through show-gateways-and-servers at details-level 'full'.

    Can't use CPClient.paginate() here — it hardcodes details-level to 'standard',
    which omits 'version' and 'os-name' entirely (confirmed against a real management
    server: 'standard' returns version=None for every gateway regardless of what
    version it actually runs; 'full' returns the real string, e.g. 'R82.20')."""
    results = []
    offset = 0
    limit = 200
    total = None
    while total is None or offset < total:
        page = client.call("show-gateways-and-servers", target,
                            {"limit": limit, "offset": offset, "details-level": "full"})
        total = page.get("total", 0)
        results.extend(page.get("objects", []))
        offset += limit
        if offset >= total:
            break
    return results


def list_gateways(client: CPClient, target: str) -> list[Gateway]:
    raw = _fetch_full_gateways(client, target)
    gateways = []
    for gw in raw:
        blades = [k for k in BLADE_KEYS
                  if gw.get(k) is True or (isinstance(gw.get(k), dict) and gw[k].get("enabled"))]
        gateways.append(Gateway(
            name=gw.get("name", gw.get("uid", "")),
            uid=gw.get("uid", ""),
            type=gw.get("type", ""),
            version=gw.get("version", ""),
            os_name=gw.get("os-name", ""),
            blades=blades,
        ))
    return gateways
