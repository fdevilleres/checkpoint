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


def list_gateways(client: CPClient, target: str) -> list[Gateway]:
    raw = client.paginate("show-gateways-and-servers", target, key="objects")
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
