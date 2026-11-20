"""Diagnosis along Mac → Wi-Fi → router → ISP → VPN → DNS → sites, and the conclusions."""

import copy
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import probes as p
from .i18n import country_name, fmt_ms, t, tr_error
from .report import (
    ACTIVE,
    FAIL,
    OK,
    PENDING,
    SKIP,
    WARN,
    Report,
    reason_of,
    score_network,
)

SITES = [
    ("Google", "www.google.com"),
    ("YouTube", "www.youtube.com"),
    ("Telegram", "web.telegram.org"),
    ("WhatsApp", "web.whatsapp.com"),
    ("Instagram", "www.instagram.com"),
    ("ChatGPT", "chatgpt.com"),
    ("Claude", "claude.ai"),
    ("GitHub", "github.com"),
    ("Discord", "discord.com"),
    ("Yandex", "ya.ru"),
]
PING_TARGETS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Yandex", "77.88.8.8")]
DNS_SERVERS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Yandex", "77.88.8.8")]
DIRECT_RESOLVERS = ["77.88.8.8", "1.1.1.1", "8.8.8.8"]

PHRASES = {
    "scan": ("phrase.scan.1", "phrase.scan.2"),
    "link": ("phrase.link.1", "phrase.link.2"),
    "link_eth": ("phrase.link_eth",),
    "router": ("phrase.router.1", "phrase.router.2"),
    "isp": ("phrase.isp.1", "phrase.isp.2"),
    "vpn": ("phrase.vpn.1", "phrase.vpn.2"),
    "dns": ("phrase.dns.1", "phrase.dns.2"),
    "sites": ("phrase.sites.1", "phrase.sites.2"),
}


class Doctor:
    def __init__(self, sites=None, quick=False):
        self.sites = sites or SITES
        self.quick = quick
        self.lock = threading.Lock()
        self._wifi_future = None
        self.report = Report(started=time.perf_counter(), phrase=t(PHRASES["scan"][0]), mood="think")
        for key, label in (("mac", "Mac"), ("link", "node.link"), ("router", "node.router"),
                           ("isp", "node.isp"), ("dns", "DNS"), ("sites", "node.sites")):
            self.node(key, label=t(label) if label.startswith("node.") else label)

    # ───────────────────────── internals ─────────────────────────

    def snapshot(self):
        """A copy of the report for the screen. The live view reads only this."""
        with self.lock:
            return copy.deepcopy(self.report)

    def _publish(self, **fields):
        with self.lock:
            for key, value in fields.items():
                setattr(self.report, key, value)

    def say(self, key):
        with self.lock:
            self.report.phrase = t(random.choice(PHRASES[key]))

    def log(self, level, text):
        with self.lock:
            self.report.events.append((level, text))

    def finding(self, level, title, tip):
        with self.lock:
            self.report.findings.append((level, title, tip))

    def _set_finding(self, index, item):
        with self.lock:
            self.report.findings[index] = item

    def node(self, key, status=None, value=None, label=None):
        with self.lock:
            n = self.report.nodes.setdefault(key, {"label": label or key, "status": PENDING, "value": ""})
            if key not in self.report.node_order:
                self.report.node_order.append(key)
            if label:
                n["label"] = label
            if status:
                n["status"] = status
                if status in (WARN, FAIL) and self.report.mood == "think":
                    self.report.mood = "worried"
            if value is not None:
                n["value"] = value

    @property
    def effective_iface(self):
        return self.report.phys

    # ───────────────────────── steps ─────────────────────────

    def run(self):
        pool = ThreadPoolExecutor(max_workers=24)
        try:
            if not self.step_scan(pool):
                return self.finish()
            self.step_link()
            if not self.step_router(pool):
                return self.finish()
            isp_up = self.step_isp(pool)
            if self.report.vpn:
                if isp_up:
                    self.step_vpn(pool)
                else:
                    self.node("vpn", SKIP, t("value.no_channel"))
                    self.log(SKIP, t("log.skip_vpn"))
            self.step_dns(pool)
            if isp_up:
                self.step_sites(pool)
            else:
                self.node("sites", SKIP, t("value.skipped"))
                self.log(SKIP, t("log.skip_sites"))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        self.finish()

    def step_scan(self, pool):
        self.say("scan")
        self.node("mac", ACTIVE)
        self._wifi_future = pool.submit(p.wifi_info)
        routes = p.default_routes()
        ports = p.hardware_ports()
        sys_dns = p.system_dns()
        vpn = False
        vpn_iface = None
        vpn_apps = []
        if routes and p.is_tunnel(routes[0][1]):
            vpn, vpn_iface = True, routes[0][1]
            vpn_apps = p.running_vpn_apps()
        phys_routes = [r for r in routes if not p.is_tunnel(r[1])]
        if not phys_routes and vpn:
            # A tunnel exists, but no physical route is visible — try Wi-Fi or Ethernet directly.
            for dev in ports:
                gw = p.sh(["ipconfig", "getoption", dev, "router"]).strip() if p.IS_MAC else ""
                if gw:
                    phys_routes = [(gw, dev)]
                    break
        self.node("mac", OK, p.sh(["hostname", "-s"]).strip()[:14] or t("value.this_mac"))
        self._publish(sys_dns=sys_dns)
        if not phys_routes:
            self.log(FAIL, t("log.no_route"))
            self.node("link", FAIL, t("value.no_link"))
            self.finding(FAIL, t("find.no_network"), t("tip.no_network"))
            return False
        gw, phys = phys_routes[0]
        port_name = ports.get(phys) or ("Wi-Fi" if phys == "en0" else phys)
        local_ip = p.iface_ip(phys)
        self._publish(vpn=vpn, vpn_iface=vpn_iface, vpn_apps=vpn_apps,
                      gw=gw, phys=phys, port_name=port_name, local_ip=local_ip)
        self.log(OK, t("log.iface", port=port_name, phys=phys, ip=local_ip or "?"))
        no_access = p.network_blocked(gw, phys)
        if no_access:
            self._publish(no_access=no_access)
            self.log(FAIL, t("log.no_access", reason=no_access))
            self.node("link", OK, phys, label="Wi-Fi" if "wi-fi" in (port_name or "").lower() else t("node.cable"))
            self.node("router", FAIL, t("value.no_access"))
            self.finding(FAIL, t("find.sandbox"), t("tip.sandbox"))
            return False
        if vpn:
            self.node("vpn", label="VPN")
            with self.lock:
                order = self.report.node_order
                order.remove("vpn")
                order.insert(order.index("isp") + 1, "vpn")
            app = vpn_apps[0] if vpn_apps else "VPN"
            self.log(OK, t("log.tunnel", iface=vpn_iface, app=app))
        return True

    def step_link(self):
        port_name = self.report.port_name
        phys = self.report.phys
        is_wifi = "wi-fi" in (port_name or "").lower() or "airport" in (port_name or "").lower()
        self.node("link", ACTIVE, label="Wi-Fi" if is_wifi else t("node.cable"))
        self.say("link" if is_wifi else "link_eth")
        if not is_wifi:
            self.node("link", OK, phys)
            return
        try:
            wifi = self._wifi_future.result(timeout=15)
        except Exception:
            wifi = None
        self._publish(wifi=wifi)
        if not wifi or wifi.get("signal") is None:
            self.node("link", OK, phys)
            self.log(OK, t("log.wifi_on"))
            return
        sig = wifi["signal"]
        snr = sig - wifi["noise"] if wifi.get("noise") is not None else None
        band = t("band.5") if "5GHz" in (wifi.get("channel") or "") else (t("band.6") if "6GHz" in (wifi.get("channel") or "") else t("band.24"))
        if sig >= -67:
            self.node("link", OK, "%d dBm" % sig)
            self.log(OK, t("log.wifi_ok", band=band, sig=sig, phy=wifi.get("phy") or "", word=signal_word(sig)))
        elif sig >= -75:
            self.node("link", WARN, "%d dBm" % sig)
            self.log(WARN, t("log.wifi_weak", sig=sig))
            self.finding(WARN, t("find.wifi_weak", sig=sig), t("tip.wifi_weak"))
        else:
            self.node("link", FAIL, "%d dBm" % sig)
            self.log(FAIL, t("log.wifi_bad", sig=sig))
            self.finding(FAIL, t("find.wifi_bad", sig=sig), t("tip.wifi_bad"))
        if band == t("band.24") and sig >= -67:
            self.finding(WARN, t("find.band"), t("tip.band"))
        if snr is not None and snr < 20:
            self.finding(WARN, t("find.snr", snr=snr), t("tip.snr"))

    def step_router(self, pool):
        self.say("router")
        self.node("router", ACTIVE)
        gw, phys = self.report.gw, self.report.phys
        brand_f = pool.submit(p.router_brand, gw, phys)
        r = p.ping(gw, count=8 if self.quick else 15, interval=0.2, iface=phys)
        brand = brand_f.result()
        self._publish(router_ping=r, router_brand=brand)
        name = brand or gw
        if r["recv"] == 0:
            self.node("router", FAIL, t("value.silent"))
            self.log(FAIL, t("log.router_silent", gw=gw))
            self.finding(FAIL, t("find.router_down"), t("tip.router_down"))
            # Some routers simply drop ping — check whether the internet works beyond them.
            probe = p.ping("1.1.1.1", count=3, iface=phys)
            if probe["recv"]:
                self._set_finding(-1, (WARN, t("find.router_ignore"), t("tip.router_ignore")))
                self.node("router", WARN, t("value.no_ping"))
                return True
            return False
        status = OK
        if r["loss"] > 10 or r["avg"] > 30:
            status = FAIL
        elif r["loss"] > 0 or r["avg"] > 12 or r["jitter"] > 10:
            status = WARN
        self.node("router", status, fmt_ms(r["avg"]))
        self.log(status, t("log.router", name=name, avg=r["avg"], jitter=r["jitter"], loss=r["loss"]))
        if status != OK:
            self.finding(status, t("find.router_unstable", loss=r["loss"], avg=r["avg"]), t("tip.router_unstable"))
        return True

    def step_isp(self, pool):
        self.say("isp")
        self.node("isp", ACTIVE)
        phys = self.report.phys
        cnt = 6 if self.quick else 10
        futs = [pool.submit(p.ping, ip, cnt, 0.2, phys) for _, ip in PING_TARGETS]
        meta_ips = self._direct_ips("speed.cloudflare.com")
        meta_ip = meta_ips[0] if meta_ips else None
        meta_f = pool.submit(p.cf_meta, phys, meta_ip) if meta_ip else None
        cap_f = pool.submit(p.captive_portal, phys)
        v6_f = pool.submit(p.ipv6_available)
        pings = [(name, f.result()) for (name, _), f in zip(PING_TARGETS, futs)]
        meta = (meta_f.result() if meta_f else None) or None
        captive = cap_f.result()
        ipv6 = v6_f.result()
        self._publish(isp_pings=pings, meta_direct=meta, captive=captive, ipv6=ipv6)
        alive = [r for _, r in pings if r["recv"]]
        org = (meta or {}).get("asOrganization")
        if not alive and not meta:
            self.node("isp", FAIL, t("value.no_link"))
            self.log(FAIL, t("log.isp_down"))
            self.finding(FAIL, t("find.isp_down"), t("tip.isp_down"))
            return False
        best = min(r["avg"] for r in alive) if alive else None
        loss = max(r["loss"] for r in alive) if alive else 0
        status = OK
        if best is not None and (best > 80 or loss > 10):
            status = FAIL if loss > 20 else WARN
        elif loss > 0 or (best is not None and best > 40):
            status = WARN
        self.node("isp", status, fmt_ms(best) if best is not None else t("value.no_ping"))
        latency = fmt_ms(pings[0][1]["avg"]) if pings[0][1]["avg"] else "—"
        self.log(status, t("log.isp", org=short_org(org) or "?", latency=latency, loss=loss))
        if status != OK and best is not None:
            self.finding(status, t("find.isp_unstable", best=best, loss=loss), t("tip.isp_unstable"))
        if captive:
            self.finding(FAIL, t("find.captive"), t("tip.captive"))
            self.log(FAIL, t("log.captive"))
        return True

    def step_vpn(self, pool):
        self.say("vpn")
        self.node("vpn", ACTIVE)
        meta_f = pool.submit(p.cf_meta)
        vpn_rtt = p.http_rtt()
        meta = meta_f.result() or None
        self._publish(vpn_rtt=vpn_rtt, meta_vpn=meta)
        app = self.report.vpn_apps[0] if self.report.vpn_apps else "VPN"
        if not meta and vpn_rtt is None:
            self.node("vpn", FAIL, t("value.no_route"))
            self.log(FAIL, t("log.vpn_dead", app=app))
            self.finding(FAIL, t("find.vpn_dead"), t("tip.vpn_dead", app=app))
            return
        cc = (meta or {}).get("country")
        status = OK if (vpn_rtt or 0) < 250 else WARN
        self.node("vpn", status, "%s · %s" % (flag(cc), fmt_ms(vpn_rtt) if vpn_rtt else ""))
        self.log(status, t("log.vpn_ok", app=app, country=country_name(cc),
                           org=short_org((meta or {}).get("asOrganization")) or "?",
                           latency=fmt_ms(vpn_rtt) if vpn_rtt else "?"))
        if status == WARN:
            self.finding(WARN, t("find.vpn_slow", rtt=vpn_rtt), t("tip.vpn_slow"))

    def _direct_ips(self, host, limit=3):
        ips = []
        for srv in DIRECT_RESOLVERS:
            d = p.dns_query(srv, host, self.report.phys)
            for ip in d["ips"]:
                if ip not in ips:
                    ips.append(ip)
                    if len(ips) >= limit:
                        return ips
        return ips

    def _probe_direct(self, host):
        attempts = [
            p.http_probe(host, ip=ip, iface=self.report.phys, timeout=5)
            for ip in self._direct_ips(host)
        ]
        if not attempts:
            return {"host": host, "ip": None, "dns": None, "tcp": None, "tls": None, "http": None,
                    "status": None, "stage": "dns", "error": "domain does not resolve"}
        for result in attempts:
            if not result["error"]:
                return result
        stage_rank = {"dns": 0, "tcp": 1, "tls": 2, "http": 3}
        return max(attempts, key=lambda r: stage_rank.get(r["stage"], -1))

    def _record_site_result(self, result):
        with self.lock:
            self.report.site_results.append(result)
            done = len(self.report.site_results)
            self.report.nodes["sites"]["value"] = "%d/%d" % (done, len(self.sites))
            return done

    def step_dns(self, pool):
        self.say("dns")
        self.node("dns", ACTIVE)
        names = ["github.com", "wikipedia.org", "apple.com"]
        resolved = list(pool.map(p.resolve_system, names))
        servers = list(DNS_SERVERS)
        if self.report.gw:
            servers.append((t("node.router"), self.report.gw))

        def check(item):
            name, srv = item
            return (name, srv, p.dns_query(srv, "example.com", self.report.phys),
                    p.dns_query(srv, "www.youtube.com", self.report.phys))

        table = list(pool.map(check, servers))
        self._publish(sys_resolve=resolved, dns_table=table)
        ok = [r for r in resolved if r["ips"]]
        fake = any(p.ip_kind(ip) == "fake" for r in ok for ip in r["ips"])
        sys_dns = self.report.sys_dns
        if not ok:
            self.node("dns", FAIL, t("value.broken"))
            self.log(FAIL, t("log.dns_down", dns=sys_dns or "?"))
            working = [n for n, _, c, _ in table if c["ips"]]
            extra = t("tip.dns_extra", names=", ".join(working)) if working else ""
            self.finding(FAIL, t("find.dns_down"), t("tip.dns_down", extra=extra))
            return
        avg = sum(r["ms"] for r in ok) / len(ok)
        status = OK if len(ok) == len(names) and avg < 150 else WARN
        self.node("dns", status, "fake-ip" if fake else fmt_ms(avg))
        if fake:
            self.log(OK, t("log.dns_fake"))
        else:
            self.log(status, t("log.dns", dns=sys_dns or "", avg=avg))
        if status == WARN and not fake:
            self.finding(WARN, t("find.dns_slow", avg=avg), t("tip.dns_slow"))
        filtered = [n for n, _, c, s in table if c["ips"] and not s["ips"]]
        if filtered:
            names = ", ".join(filtered)
            self.log(WARN, t("log.dns_filter", names=names))
            via = t("tip.dns_filter_vpn") if self.report.vpn else t("tip.dns_filter")
            self.finding(WARN, t("find.dns_filter", names=names), via)

    def step_sites(self, pool):
        self.say("sites")
        self.node("sites", ACTIVE, "0/%d" % len(self.sites))
        use_vpn = self.report.vpn
        vpn_app = self.report.vpn_apps[0] if self.report.vpn_apps else "VPN"

        def probe(item):
            name, host = item
            via = p.http_probe(host) if use_vpn else None
            direct = self._probe_direct(host)
            res = (name, host, via, direct)
            eff = via if use_vpn else direct
            self._record_site_result(res)
            if eff["error"]:
                self.log(FAIL, "%s: %s" % (name, tr_error(eff["error"])))
            return res

        list(pool.map(probe, self.sites))
        order = {h: i for i, (_, h) in enumerate(self.sites)}
        with self.lock:
            self.report.site_results.sort(key=lambda r: order[r[1]])
            results = list(self.report.site_results)
        eff = [(n, (v if use_vpn else d)) for n, _, v, d in results]
        bad = [n for n, r in eff if r["error"]]
        slow = [n for n, r in eff if not r["error"] and p.total_ms(r) > 2500]
        okn = len(eff) - len(bad)
        status = OK if not bad and not slow else (FAIL if len(bad) > len(eff) // 2 else WARN)
        self.node("sites", status, "%d/%d" % (okn, len(eff)))
        if bad:
            reasons = {}
            for n, r in eff:
                if r["error"]:
                    reasons.setdefault(reason_of(r), []).append(n)
            for why, names in reasons.items():
                if use_vpn:
                    tip = t("tip.sites_vpn", app=vpn_app)
                else:
                    tip = {
                        "dpi": t("tip.sites_dpi"),
                        "ip": t("tip.sites_ip"),
                        "dns": t("tip.sites_dns"),
                    }.get(why, t("tip.sites_other"))
                self.finding(FAIL, t("find.sites_bad", names=", ".join(names), reason=t(REASON_TEXT[why])), tip)
        if slow:
            self.finding(WARN, t("find.sites_slow", names=", ".join(slow)), t("tip.sites_slow"))
        blocked_direct = [n for n, _, v, d in results if d["error"]]
        if use_vpn and blocked_direct:
            saved = [n for n, _, v, d in results if d["error"] and v and not v["error"]]
            if saved:
                self.finding(OK, t("find.sites_saved", names=", ".join(saved)), t("tip.sites_saved"))
        unneeded = [n for n, _, v, d in results if use_vpn and not d["error"] and v and v["error"]]
        if unneeded:
            self.finding(WARN, t("find.sites_direct", names=", ".join(unneeded)), t("tip.sites_direct"))

    # ───────────────────────── finish ─────────────────────────

    def finish(self):
        with self.lock:
            r = self.report
            r.score = score_network(r.findings, r.nodes, r.router_ping, r.captive, r.no_access)
            fails = [f for f in r.findings if f[0] == FAIL]
            warns = [f for f in r.findings if f[0] == WARN]
            if fails:
                r.mood = "sad" if (r.score or 0) < 40 else "worried"
                r.headline = fails[0][1]
            elif warns:
                r.mood = "worried" if (r.score or 0) < 75 else "normal"
                r.headline = t("headline.warn")
            else:
                r.mood = "happy"
                r.headline = t("headline.ok")
            r.phrase = r.headline
            for n in r.nodes.values():
                if n["status"] in (PENDING, ACTIVE):
                    n["status"] = SKIP
            r.done = True


# ───────────────────────── helpers ─────────────────────────

REASON_TEXT = {
    "dpi": "reason.dpi",
    "ip": "reason.ip",
    "dns": "reason.dns",
    "cert": "reason.cert",
    "other": "reason.other",
}


def signal_word(sig):
    if sig >= -55:
        return t("signal.excellent")
    if sig >= -67:
        return t("signal.good")
    if sig >= -75:
        return t("signal.weak")
    return t("signal.very_weak")


def short_org(org):
    if not org:
        return None
    for junk in (" customers", " Broadband", " LLC", " Ltd", " GmbH", " Inc.", " AS"):
        org = org.replace(junk, "")
    return org.strip()[:28]


def flag(cc):
    return cc or ""
