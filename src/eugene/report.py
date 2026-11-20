"""The diagnosis snapshot. The screen is drawn from it, and JSON is built from it.

Node levels are shared by the doctor and the score. Change the string here,
not in two files at once.
"""

from __future__ import annotations

PENDING, ACTIVE, OK, WARN, FAIL, SKIP = "pending", "active", "ok", "warn", "fail", "skip"

# Points removed for a finding, and the cap when a chain node is fully dead.
_PENALTY = {FAIL: 22, WARN: 7}
_CAPS = {"link": 0, "router": 10, "isp": 10, "dns": 25, "vpn": 30}

from dataclasses import dataclass, field

from .probes import total_ms


@dataclass
class Report:
    started: float = 0.0
    phrase: str = ""
    mood: str = "think"
    done: bool = False
    headline: str = ""
    score: int | None = None
    events: list = field(default_factory=list)
    nodes: dict = field(default_factory=dict)
    node_order: list = field(default_factory=list)
    vpn: bool = False
    vpn_iface: str | None = None
    vpn_apps: list = field(default_factory=list)
    phys: str | None = None
    gw: str | None = None
    port_name: str | None = None
    local_ip: str | None = None
    wifi: dict | None = None
    router_ping: dict | None = None
    router_brand: str | None = None
    isp_pings: list = field(default_factory=list)
    meta_direct: dict | None = None
    meta_vpn: dict | None = None
    vpn_rtt: float | None = None
    captive: bool | None = None
    ipv6: bool | None = None
    sys_dns: str | None = None
    sys_resolve: list = field(default_factory=list)
    dns_table: list = field(default_factory=list)
    site_results: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    no_access: str | None = None


def score_network(findings, nodes, router_ping=None, captive=False, no_access=None):
    """Network health from 0 to 100. None when the program is denied network access.

    Findings apply penalties first, then a dead link in the chain caps the score.
    Without internet, a couple of warnings cannot leave the result looking almost healthy.
    """
    if no_access:
        return None
    score = 100.0
    for level, _title, _tip in findings:
        score -= _PENALTY.get(level, 0)
    avg = (router_ping or {}).get("avg")
    if avg:
        score -= min(8.0, max(0.0, (avg - 5) / 3))
    for key, cap in _CAPS.items():
        if nodes.get(key, {}).get("status") == FAIL:
            score = min(score, cap)
    if captive:
        score = min(score, 20)
    return int(max(0, min(100, round(score))))


def reason_of(r):
    if r["stage"] == "dns":
        return "dns"
    if r["error"] == "untrusted certificate":
        return "cert"
    if r["stage"] == "tls" or r["stage"] == "http":
        return "dpi"
    if r["stage"] == "tcp":
        return "ip"
    return "other"


def to_json(rep):
    def site(r):
        if r is None:
            return None
        return {
            "ok": not r["error"],
            "error": r["error"],
            "stage": r["stage"],
            "status": r["status"],
            "ms": round(total_ms(r), 1),
            "reason": reason_of(r) if r["error"] else None,
        }

    return {
        "score": rep.score,
        "headline": rep.headline,
        "interface": rep.phys,
        "router": rep.gw,
        "router_brand": rep.router_brand,
        "wifi": rep.wifi,
        "router_ping": rep.router_ping and {k: rep.router_ping[k] for k in ("avg", "jitter", "loss")},
        "isp": (rep.meta_direct or {}).get("asOrganization"),
        "vpn": {
            "active": rep.vpn,
            "apps": rep.vpn_apps,
            "exit_country": (rep.meta_vpn or {}).get("country"),
            "rtt_ms": rep.vpn_rtt,
        } if rep.vpn else {"active": False},
        "pings": {r["host"]: {k: r[k] for k in ("avg", "jitter", "loss")} for _, r in rep.isp_pings},
        "dns": {"system": rep.sys_dns},
        "sites": {name: {"via_vpn": site(v), "direct": site(d)} for name, _, v, d in rep.site_results},
        "findings": [{"level": level, "title": title, "tip": tip} for level, title, tip in rep.findings],
    }
