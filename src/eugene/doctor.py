"""Diagnosis along Mac → Wi-Fi → router → ISP → VPN → DNS → sites, and the conclusions."""

import copy
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import probes as p
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
    "scan": ["Looking around the burrow for network interfaces", "Antennae up — what kind of network is this?"],
    "link": ["Poking the Wi-Fi with a claw…", "Sniffing the airwaves…"],
    "link_eth": ["Checking the cable — is it seated?"],
    "router": ["Knock knock, router", "Tapping the router…"],
    "isp": ["Sidling toward the ISP…", "Peeking past the router — is the internet there?"],
    "vpn": ["Diving into the VPN tunnel… blub", "Swimming toward the VPN exit…"],
    "dns": ["Sniffing the DNS…", "Asking the DNS servers for directions…"],
    "sites": ["Clicking through sites with a claw…", "Walking the usual sites, one by one…"],
}


class Doctor:
    def __init__(self, sites=None, quick=False):
        self.sites = sites or SITES
        self.quick = quick
        self.lock = threading.Lock()
        self._wifi_future = None
        self.report = Report(started=time.perf_counter(), phrase=PHRASES["scan"][0], mood="think")
        for key, label in (("mac", "Mac"), ("link", "Link"), ("router", "Router"),
                           ("isp", "ISP"), ("dns", "DNS"), ("sites", "Sites")):
            self.node(key, label=label)

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
            self.report.phrase = random.choice(PHRASES[key])

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
                    self.node("vpn", SKIP, "no link")
                    self.log(SKIP, "Skipping VPN: the internet is unreachable even directly")
            self.step_dns(pool)
            if isp_up:
                self.step_sites(pool)
            else:
                self.node("sites", SKIP, "skipped")
                self.log(SKIP, "Skipping sites: there is no internet beyond the router")
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
        self.node("mac", OK, p.sh(["hostname", "-s"]).strip()[:14] or "this Mac")
        self._publish(sys_dns=sys_dns)
        if not phys_routes:
            self.log(FAIL, "No route to the internet: the Mac is not on Wi-Fi or a cable")
            self.node("link", FAIL, "no link")
            self.finding(FAIL, "No network connection",
                         "Turn on Wi-Fi or check the cable. If Wi-Fi is connected, reconnect to the network.")
            return False
        gw, phys = phys_routes[0]
        port_name = ports.get(phys) or ("Wi-Fi" if phys == "en0" else phys)
        local_ip = p.iface_ip(phys)
        self._publish(vpn=vpn, vpn_iface=vpn_iface, vpn_apps=vpn_apps,
                      gw=gw, phys=phys, port_name=port_name, local_ip=local_ip)
        self.log(OK, "Interface %s (%s), address %s" % (port_name, phys, local_ip or "?"))
        no_access = p.network_blocked(gw, phys)
        if no_access:
            self._publish(no_access=no_access)
            self.log(FAIL, "Sockets are rejected before any packet is sent: %s" % no_access)
            self.node("link", OK, phys, label="Wi-Fi" if "wi-fi" in (port_name or "").lower() else "Cable")
            self.node("router", FAIL, "no access")
            self.finding(FAIL, "This terminal has no network access",
                         "The system will not let the program open connections — the router is not the problem. "
                         "Run eugene in Terminal.app or iTerm. If it still fails, check a firewall "
                         "(Little Snitch, LuLu) or device-management profiles.")
            return False
        if vpn:
            self.node("vpn", label="VPN")
            with self.lock:
                order = self.report.node_order
                order.remove("vpn")
                order.insert(order.index("isp") + 1, "vpn")
            app = vpn_apps[0] if vpn_apps else "VPN"
            self.log(OK, "Traffic goes through tunnel %s — looks like %s" % (vpn_iface, app))
        return True

    def step_link(self):
        port_name = self.report.port_name
        phys = self.report.phys
        is_wifi = "wi-fi" in (port_name or "").lower() or "airport" in (port_name or "").lower()
        self.node("link", ACTIVE, label="Wi-Fi" if is_wifi else "Cable")
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
            self.log(OK, "Wi-Fi is connected")
            return
        sig = wifi["signal"]
        snr = sig - wifi["noise"] if wifi.get("noise") is not None else None
        band = "5 GHz" if "5GHz" in (wifi.get("channel") or "") else ("6 GHz" if "6GHz" in (wifi.get("channel") or "") else "2.4 GHz")
        if sig >= -67:
            self.node("link", OK, "%d dBm" % sig)
            self.log(OK, "Wi-Fi %s: signal %d dBm, %s — %s" % (band, sig, wifi.get("phy") or "", signal_word(sig)))
        elif sig >= -75:
            self.node("link", WARN, "%d dBm" % sig)
            self.log(WARN, "Wi-Fi signal is a bit weak: %d dBm" % sig)
            self.finding(WARN, "Weak Wi-Fi signal (%d dBm)" % sig,
                         "Move closer to the router or clear obstructions. −67 dBm or stronger is more stable.")
        else:
            self.node("link", FAIL, "%d dBm" % sig)
            self.log(FAIL, "Wi-Fi signal is very weak: %d dBm" % sig)
            self.finding(FAIL, "Very weak Wi-Fi (%d dBm)" % sig,
                         "The link will drop. Move closer to the router, or add a repeater or mesh.")
        if band == "2.4 GHz" and sig >= -67:
            self.finding(WARN, "Wi-Fi is on 2.4 GHz",
                         "This band is slower and noisier. If the router offers 5 GHz, use that.")
        if snr is not None and snr < 20:
            self.finding(WARN, "A lot of radio noise (SNR %d dB)" % snr,
                         "Change the Wi-Fi channel in the router settings to a less crowded one.")

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
            self.node("router", FAIL, "silent")
            self.log(FAIL, "Router %s does not answer ping" % gw)
            self.finding(FAIL, "Router does not answer",
                         "Check that the router is on, then power-cycle it for 10 seconds.")
            # Some routers simply drop ping — check whether the internet works beyond them.
            probe = p.ping("1.1.1.1", count=3, iface=phys)
            if probe["recv"]:
                self._set_finding(-1, (WARN, "Router does not answer ping",
                                       "The internet still works, so the router is probably ignoring ping."))
                self.node("router", WARN, "no ping")
                return True
            return False
        status = OK
        if r["loss"] > 10 or r["avg"] > 30:
            status = FAIL
        elif r["loss"] > 0 or r["avg"] > 12 or r["jitter"] > 10:
            status = WARN
        self.node("router", status, "%.0f ms" % r["avg"] if r["avg"] >= 10 else "%.1f ms" % r["avg"])
        self.log(status, "Router %s: %.1f ms, jitter %.1f, loss %.0f%%" % (name, r["avg"], r["jitter"], r["loss"]))
        if status != OK:
            self.finding(status, "Unstable link to the router (%.0f%% loss, %.0f ms)" % (r["loss"], r["avg"]),
                         "The problem is between the Mac and the router: usually Wi-Fi noise, distance, or an overloaded router.")
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
            self.node("isp", FAIL, "no link")
            self.log(FAIL, "Silence beyond the router: no internet server answers")
            self.finding(FAIL, "No internet beyond the router",
                         "The router is up, but nothing gets out. Power-cycle it. If that does not help, call the ISP "
                         "and check the account balance.")
            return False
        best = min(r["avg"] for r in alive) if alive else None
        loss = max(r["loss"] for r in alive) if alive else 0
        status = OK
        if best is not None and (best > 80 or loss > 10):
            status = FAIL if loss > 20 else WARN
        elif loss > 0 or (best is not None and best > 40):
            status = WARN
        self.node("isp", status, ("%.0f ms" % best) if best is not None else "no ping")
        self.log(status, "ISP %s: to 1.1.1.1 %s, loss %.0f%%" % (
            short_org(org) or "?", ("%.0f ms" % pings[0][1]["avg"]) if pings[0][1]["avg"] else "—", loss))
        if status != OK and best is not None:
            self.finding(status, "The ISP link is unstable (%.0f ms, up to %.0f%% loss)" % (best, loss),
                         "If the router still answers quickly, the problem is at the ISP. Power-cycle the router, "
                         "and contact support if it keeps happening.")
        if captive:
            self.finding(FAIL, "This network requires a sign-in",
                         "This is a captive portal (cafe, hotel, transit). Open any http site and sign in.")
            self.log(FAIL, "Captive portal detected — sign-in required")
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
            self.node("vpn", FAIL, "no route")
            self.log(FAIL, "%s is on, but traffic does not pass through the tunnel" % app)
            self.finding(FAIL, "VPN is not passing traffic",
                         "%s brought the tunnel up, but nothing gets through. Switch servers or restart the VPN." % app)
            return
        cc = (meta or {}).get("country")
        status = OK if (vpn_rtt or 0) < 250 else WARN
        self.node("vpn", status, "%s · %s" % (flag(cc), ("%.0f ms" % vpn_rtt) if vpn_rtt else ""))
        self.log(status, "%s → exit: %s (%s), latency %s" % (
            app, country_name(cc), short_org((meta or {}).get("asOrganization")) or "?",
            ("%.0f ms" % vpn_rtt) if vpn_rtt else "?"))
        if status == WARN:
            self.finding(WARN, "Slow VPN server (%.0f ms)" % vpn_rtt,
                         "The server is far away or overloaded. Pick a closer one — Finland, the Netherlands, or Germany.")

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
            servers.append(("Router", self.report.gw))

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
            self.node("dns", FAIL, "broken")
            self.log(FAIL, "System DNS (%s) does not answer" % (sys_dns or "?"))
            working = [n for n, _, c, _ in table if c["ips"]]
            self.finding(FAIL, "DNS is broken — sites will not open by name",
                         ("Set DNS manually: System Settings → Network → Details → DNS → 1.1.1.1 and 77.88.8.8."
                          + (" These answer directly: %s." % ", ".join(working) if working else "")))
            return
        avg = sum(r["ms"] for r in ok) / len(ok)
        status = OK if len(ok) == len(names) and avg < 150 else WARN
        self.node("dns", status, "fake-ip" if fake else "%.0f ms" % avg)
        if fake:
            self.log(OK, "DNS answers with 198.18.x.x stand-ins — the VPN fake-ip mode, which is fine")
        else:
            self.log(status, "DNS %s answers in %.0f ms" % (sys_dns or "", avg))
        if status == WARN and not fake:
            self.finding(WARN, "DNS is slow (%.0f ms)" % avg,
                         "Every new site opens late. Try DNS 1.1.1.1 or 77.88.8.8.")
        filtered = [n for n, _, c, s in table if c["ips"] and not s["ips"]]
        if filtered:
            self.log(WARN, "DNS %s does not know youtube.com — the ISP is rewriting answers" % ", ".join(filtered))
            via = "Queries to public DNS are intercepted, and blocked domains disappear. DNS-over-HTTPS or a VPN gets around it."
            if self.report.vpn:
                via = "The ISP intercepts queries to public DNS. The VPN path is not affected."
            self.finding(WARN, "The ISP filters DNS (%s)" % ", ".join(filtered), via)

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
                self.log(FAIL, "%s: %s" % (name, eff["error"]))
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
                    tip = "It does not open through the VPN. Change the server in %s or check the routing rules." % vpn_app
                else:
                    tip = {
                        "dpi": "This looks like DPI blocking. A VPN or another bypass is needed.",
                        "ip": "The site address is unreachable — an IP block, or a problem on the site's side.",
                        "dns": "DNS returns no address — a DNS block. DoH or a VPN can help.",
                    }.get(why, "Try again later, or through a VPN.")
                self.finding(FAIL, "Will not open: %s — %s" % (", ".join(names), REASON_TEXT[why]), tip)
        if slow:
            self.finding(WARN, "Slow to open: %s" % ", ".join(slow),
                         "The sites are reachable, but they take more than 2.5 s — the link or VPN server is overloaded.")
        blocked_direct = [n for n, _, v, d in results if d["error"]]
        if use_vpn and blocked_direct:
            saved = [n for n, _, v, d in results if d["error"] and v and not v["error"]]
            if saved:
                self.finding(OK, "VPN saves the day: %s" % ", ".join(saved),
                             "These sites are blocked directly and work through the tunnel.")
        unneeded = [n for n, _, v, d in results if use_vpn and not d["error"] and v and v["error"]]
        if unneeded:
            self.finding(WARN, "Works directly, but not through the VPN: %s" % ", ".join(unneeded),
                         "Add these sites to the VPN direct-exclusion list.")

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
                r.headline = "Usable overall, with a few caveats"
            else:
                r.mood = "happy"
                r.headline = "The network is healthy. This crab is on vacation!"
            r.phrase = r.headline
            for n in r.nodes.values():
                if n["status"] in (PENDING, ACTIVE):
                    n["status"] = SKIP
            r.done = True


# ───────────────────────── helpers ─────────────────────────

REASON_TEXT = {
    "dpi": "the connection breaks during TLS (DPI)",
    "ip": "the server is unreachable by IP",
    "dns": "a DNS problem",
    "cert": "the certificate was substituted",
    "other": "a connection error",
}


def signal_word(sig):
    if sig >= -55:
        return "excellent"
    if sig >= -67:
        return "good"
    if sig >= -75:
        return "weak"
    return "very weak"


def short_org(org):
    if not org:
        return None
    for junk in (" customers", " Broadband", " LLC", " Ltd", " GmbH", " Inc.", " AS"):
        org = org.replace(junk, "")
    return org.strip()[:28]


COUNTRIES = {
    "RU": "Russia", "DE": "Germany", "NL": "Netherlands", "FI": "Finland", "SE": "Sweden", "IS": "Iceland",
    "US": "United States", "GB": "United Kingdom", "FR": "France", "PL": "Poland", "LV": "Latvia", "EE": "Estonia",
    "LT": "Lithuania", "KZ": "Kazakhstan", "TR": "Turkey", "AE": "UAE", "JP": "Japan", "SG": "Singapore",
    "CH": "Switzerland", "AT": "Austria", "CZ": "Czechia", "GE": "Georgia", "AM": "Armenia", "RS": "Serbia",
    "HK": "Hong Kong", "CA": "Canada", "ES": "Spain", "IT": "Italy", "NO": "Norway", "MD": "Moldova",
}


def country_name(cc):
    return COUNTRIES.get(cc or "", cc or "?")


def flag(cc):
    return cc or ""
