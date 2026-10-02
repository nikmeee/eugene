"""Диагностика по цепочке Mac → Wi-Fi → роутер → провайдер → VPN → DNS → сайты и выводы по ней."""

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import probes as p

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
    ("Яндекс", "ya.ru"),
]
PING_TARGETS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Яндекс", "77.88.8.8")]
DNS_SERVERS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Яндекс", "77.88.8.8")]
DIRECT_RESOLVERS = ["77.88.8.8", "1.1.1.1", "8.8.8.8"]

PHRASES = {
    "scan": ["Осматриваюсь в норке… ищу сетевые интерфейсы", "Высовываю стебельки — что тут у нас за сеть?"],
    "link": ["Щупаю Wi-Fi клешнёй…", "Ловлю радиоволны усиками…"],
    "link_eth": ["Проверяю кабель — крепко держится?"],
    "router": ["Стучусь в роутер: тук-тук!", "Щёлк-щёлк по роутеру…"],
    "isp": ["Ползу боком к провайдеру…", "Выглядываю за роутер — есть там интернет?"],
    "vpn": ["Ныряю в VPN-туннель… буль!", "Плыву по туннелю к выходу VPN…"],
    "dns": ["Принюхиваюсь к DNS…", "Спрашиваю у DNS-серверов дорогу…"],
    "sites": ["Щёлкаю по сайтам клешнёй…", "Обхожу любимые сайты по очереди…"],
}

# статусы узлов цепочки
PENDING, ACTIVE, OK, WARN, FAIL, SKIP = "pending", "active", "ok", "warn", "fail", "skip"


class Doctor:
    def __init__(self, sites=None, quick=False):
        self.sites = sites or SITES
        self.quick = quick
        self.lock = threading.Lock()
        self.started = time.perf_counter()
        self.phrase = PHRASES["scan"][0]
        self.mood = "think"
        self.events = []  # (level, text)
        self.nodes = {}  # key -> {label, status, value}
        self.node_order = []
        self.done = False
        # результаты
        self.vpn = False
        self.vpn_iface = None
        self.vpn_apps = []
        self.phys = None  # физический интерфейс
        self.gw = None
        self.port_name = None
        self.local_ip = None
        self.wifi = None
        self.router_ping = None
        self.router_brand = None
        self.isp_pings = []
        self.meta_direct = None
        self.meta_vpn = None
        self.vpn_rtt = None
        self.captive = None
        self.ipv6 = None
        self.sys_dns = None
        self.sys_resolve = []
        self.dns_table = []  # [(name, server, control, sensitive)]
        self.site_results = []  # [(name, host, via_vpn, direct)]
        self.findings = []  # (level, title, tip)
        self.headline = ""
        self.score = None
        self.no_access = None  # текст ошибки, если программе запрещён доступ в сеть

    # ───────────────────────── служебное ─────────────────────────

    def say(self, key):
        self.phrase = random.choice(PHRASES[key])

    def log(self, level, text):
        with self.lock:
            self.events.append((level, text))

    def node(self, key, status=None, value=None, label=None):
        with self.lock:
            n = self.nodes.setdefault(key, {"label": label or key, "status": PENDING, "value": ""})
            if key not in self.node_order:
                self.node_order.append(key)
            if label:
                n["label"] = label
            if status:
                n["status"] = status
                if status in (WARN, FAIL) and self.mood == "think":
                    self.mood = "worried"
            if value is not None:
                n["value"] = value

    @property
    def effective_iface(self):
        return self.phys

    # ───────────────────────── шаги ─────────────────────────

    def run(self):
        for key, label in (("mac", "Mac"), ("link", "Сеть"), ("router", "Роутер"),
                           ("isp", "Провайдер"), ("dns", "DNS"), ("sites", "Сайты")):
            self.node(key, label=label)
        pool = ThreadPoolExecutor(max_workers=24)
        try:
            if not self.step_scan(pool):
                return self.finish()
            self.step_link()
            if not self.step_router(pool):
                return self.finish()
            self.step_isp(pool)
            if self.vpn:
                self.step_vpn(pool)
            self.step_dns(pool)
            self.step_sites(pool)
        finally:
            pool.shutdown(wait=False)
        self.finish()

    def step_scan(self, pool):
        self.say("scan")
        self.node("mac", ACTIVE)
        self._wifi_future = pool.submit(p.wifi_info)
        routes = p.default_routes()
        ports = p.hardware_ports()
        self.sys_dns = p.system_dns()
        if routes and p.is_tunnel(routes[0][1]):
            self.vpn, self.vpn_iface = True, routes[0][1]
            self.vpn_apps = p.running_vpn_apps()
        phys = [r for r in routes if not p.is_tunnel(r[1])]
        if not phys and self.vpn:
            # туннель есть, а физического маршрута не видно — пробуем Wi-Fi/ethernet напрямую
            for dev in ports:
                gw = p.sh(["ipconfig", "getoption", dev, "router"]).strip() if p.IS_MAC else ""
                if gw:
                    phys = [(gw, dev)]
                    break
        self.node("mac", OK, p.sh(["hostname", "-s"]).strip()[:14] or "этот Mac")
        if not phys:
            self.log(FAIL, "Нет маршрута в интернет: Mac не подключён ни к Wi-Fi, ни к кабелю")
            self.node("link", FAIL, "нет связи")
            self.findings.append((FAIL, "Нет подключения к сети",
                                  "Включи Wi-Fi или проверь кабель. Если Wi-Fi подключён — переподключись к сети."))
            return False
        self.gw, self.phys = phys[0]
        self.port_name = ports.get(self.phys) or ("Wi-Fi" if self.phys == "en0" else self.phys)
        self.local_ip = p.iface_ip(self.phys)
        self.log(OK, "Интерфейс %s (%s), адрес %s" % (self.port_name, self.phys, self.local_ip or "?"))
        self.no_access = p.network_blocked(self.gw, self.phys)
        if self.no_access:
            self.log(FAIL, "Сокеты отклоняются ещё до отправки пакетов: %s" % self.no_access)
            self.node("link", OK, self.phys, label="Wi-Fi" if "wi-fi" in (self.port_name or "").lower() else "Кабель")
            self.node("router", FAIL, "нет доступа")
            self.findings.append((FAIL, "У этого терминала нет доступа к сети",
                                  "Система не даёт программе открывать соединения — роутер тут ни при чём. "
                                  "Запусти netdoctor в обычном Terminal.app или iTerm. Если и там так — проверь "
                                  "фаервол (Little Snitch, LuLu) или профили управления устройством."))
            return False
        if self.vpn:
            self.node("vpn", label="VPN")
            # VPN встаёт в цепочку между провайдером и DNS
            with self.lock:
                self.node_order.remove("vpn")
                self.node_order.insert(self.node_order.index("isp") + 1, "vpn")
            app = self.vpn_apps[0] if self.vpn_apps else "VPN"
            self.log(OK, "Трафик идёт через туннель %s — похоже, это %s" % (self.vpn_iface, app))
        return True

    def step_link(self):
        is_wifi = "wi-fi" in (self.port_name or "").lower() or "airport" in (self.port_name or "").lower()
        self.node("link", ACTIVE, label="Wi-Fi" if is_wifi else "Кабель")
        self.say("link" if is_wifi else "link_eth")
        if not is_wifi:
            self.node("link", OK, self.phys)
            return
        try:
            self.wifi = self._wifi_future.result(timeout=15)
        except Exception:
            self.wifi = None
        w = self.wifi
        if not w or w.get("signal") is None:
            self.node("link", OK, self.phys)
            self.log(OK, "Wi-Fi подключён")
            return
        sig = w["signal"]
        snr = sig - w["noise"] if w.get("noise") is not None else None
        band = "5 ГГц" if "5GHz" in (w.get("channel") or "") else ("6 ГГц" if "6GHz" in (w.get("channel") or "") else "2.4 ГГц")
        if sig >= -67:
            self.node("link", OK, "%d dBm" % sig)
            self.log(OK, "Wi-Fi %s: сигнал %d dBm, %s — %s" % (band, sig, w.get("phy") or "", signal_word(sig)))
        elif sig >= -75:
            self.node("link", WARN, "%d dBm" % sig)
            self.log(WARN, "Wi-Fi сигнал слабоват: %d dBm" % sig)
            self.findings.append((WARN, "Слабый сигнал Wi-Fi (%d dBm)" % sig,
                                  "Подойди ближе к роутеру или убери преграды; для стабильности лучше −67 dBm и выше."))
        else:
            self.node("link", FAIL, "%d dBm" % sig)
            self.log(FAIL, "Wi-Fi сигнал очень слабый: %d dBm" % sig)
            self.findings.append((FAIL, "Очень слабый Wi-Fi (%d dBm)" % sig,
                                  "Связь будет рваться. Подойди к роутеру, поставь репитер или mesh."))
        if band == "2.4 ГГц" and sig >= -67:
            self.findings.append((WARN, "Wi-Fi на 2.4 ГГц",
                                  "Этот диапазон медленнее и шумнее. Если роутер умеет 5 ГГц — подключись к нему."))
        if snr is not None and snr < 20:
            self.findings.append((WARN, "Много помех в эфире (SNR %d dB)" % snr,
                                  "Смени канал Wi-Fi в настройках роутера на менее загруженный."))

    def step_router(self, pool):
        self.say("router")
        self.node("router", ACTIVE)
        brand_f = pool.submit(p.router_brand, self.gw, self.phys)
        r = p.ping(self.gw, count=8 if self.quick else 15, interval=0.2, iface=self.phys)
        self.router_ping = r
        self.router_brand = brand_f.result()
        name = self.router_brand or self.gw
        if r["recv"] == 0:
            self.node("router", FAIL, "молчит")
            self.log(FAIL, "Роутер %s не отвечает на ping" % self.gw)
            self.findings.append((FAIL, "Роутер не отвечает",
                                  "Проверь, что роутер включён; перезагрузи его (выключи на 10 секунд)."))
            # некоторые роутеры просто глушат ping — проверим, есть ли интернет дальше
            probe = p.ping("1.1.1.1", count=3, iface=self.phys)
            if probe["recv"]:
                self.findings[-1] = (WARN, "Роутер не отвечает на ping",
                                     "Интернет при этом есть — скорее всего, роутер просто игнорирует ping.")
                self.node("router", WARN, "без ping")
                return True
            return False
        status = OK
        if r["loss"] > 10 or r["avg"] > 30:
            status = FAIL
        elif r["loss"] > 0 or r["avg"] > 12 or r["jitter"] > 10:
            status = WARN
        self.node("router", status, "%.0f мс" % r["avg"] if r["avg"] >= 10 else "%.1f мс" % r["avg"])
        self.log(status, "Роутер %s: %.1f мс, джиттер %.1f, потери %.0f%%" % (name, r["avg"], r["jitter"], r["loss"]))
        if status != OK:
            self.findings.append((status, "Нестабильная связь с роутером (потери %.0f%%, %.0f мс)" % (r["loss"], r["avg"]),
                                  "Проблема между Mac и роутером: обычно это Wi-Fi — помехи, расстояние или перегруженный роутер."))
        return True

    def step_isp(self, pool):
        self.say("isp")
        self.node("isp", ACTIVE)
        cnt = 6 if self.quick else 10
        futs = [pool.submit(p.ping, ip, cnt, 0.2, self.phys) for _, ip in PING_TARGETS]
        meta_ip = self._direct_ip("speed.cloudflare.com")
        meta_f = pool.submit(p.cf_meta, self.phys, meta_ip) if meta_ip else None
        cap_f = pool.submit(p.captive_portal, self.phys)
        v6_f = pool.submit(p.ipv6_available)
        self.isp_pings = [(name, f.result()) for (name, _), f in zip(PING_TARGETS, futs)]
        self.meta_direct = (meta_f.result() if meta_f else None) or None
        self.captive = cap_f.result()
        self.ipv6 = v6_f.result()
        alive = [r for _, r in self.isp_pings if r["recv"]]
        org = (self.meta_direct or {}).get("asOrganization")
        if not alive and not self.meta_direct:
            self.node("isp", FAIL, "нет связи")
            self.log(FAIL, "За роутером тишина: ни один сервер в интернете не отвечает")
            self.findings.append((FAIL, "Нет интернета за роутером",
                                  "Роутер жив, но наружу не выходит. Перезагрузи роутер; не помогло — звони провайдеру "
                                  "(проверь и баланс)."))
            return
        best = min(r["avg"] for r in alive) if alive else None
        loss = max(r["loss"] for r in alive) if alive else 0
        status = OK
        if best is not None and (best > 80 or loss > 10):
            status = FAIL if loss > 20 else WARN
        elif loss > 0 or (best is not None and best > 40):
            status = WARN
        self.node("isp", status, ("%.0f мс" % best) if best is not None else "без ping")
        self.log(status, "Провайдер %s: до 1.1.1.1 %s, потери %.0f%%" % (
            short_org(org) or "?", ("%.0f мс" % self.isp_pings[0][1]["avg"]) if self.isp_pings[0][1]["avg"] else "—", loss))
        if status != OK and best is not None:
            self.findings.append((status, "Канал провайдера нестабилен (%.0f мс, потери до %.0f%%)" % (best, loss),
                                  "Если роутер при этом отвечает быстро — проблема у провайдера. Перезагрузи роутер, "
                                  "а если повторяется — пиши в поддержку."))
        if self.captive:
            self.findings.append((FAIL, "Сеть требует авторизации",
                                  "Это сеть с входом через браузер (кафе, отель, метро). Открой любой сайт по http и войди."))
            self.log(FAIL, "Обнаружен captive-портал — нужна авторизация")

    def step_vpn(self, pool):
        self.say("vpn")
        self.node("vpn", ACTIVE)
        meta_f = pool.submit(p.cf_meta)
        self.vpn_rtt = p.http_rtt()
        self.meta_vpn = meta_f.result() or None
        app = self.vpn_apps[0] if self.vpn_apps else "VPN"
        if not self.meta_vpn and self.vpn_rtt is None:
            self.node("vpn", FAIL, "не везёт")
            self.log(FAIL, "%s включён, но трафик через туннель не проходит" % app)
            self.findings.append((FAIL, "VPN не пропускает трафик",
                                  "%s поднял туннель, но дальше тишина. Переключи сервер или перезапусти VPN." % app))
            return
        cc = (self.meta_vpn or {}).get("country")
        status = OK if (self.vpn_rtt or 0) < 250 else WARN
        self.node("vpn", status, "%s · %s" % (flag(cc), ("%.0f мс" % self.vpn_rtt) if self.vpn_rtt else ""))
        self.log(status, "%s → выход: %s (%s), задержка %s" % (
            app, country_name(cc), short_org((self.meta_vpn or {}).get("asOrganization")) or "?",
            ("%.0f мс" % self.vpn_rtt) if self.vpn_rtt else "?"))
        if status == WARN:
            self.findings.append((WARN, "Медленный VPN-сервер (%.0f мс)" % self.vpn_rtt,
                                  "Сервер далеко или перегружен. Выбери сервер поближе — Финляндия, Нидерланды, Германия."))

    def _direct_ip(self, host):
        for srv in DIRECT_RESOLVERS:
            d = p.dns_query(srv, host, self.phys)
            if d["ips"]:
                return d["ips"][0]
        return None

    def step_dns(self, pool):
        self.say("dns")
        self.node("dns", ACTIVE)
        names = ["github.com", "wikipedia.org", "apple.com"]
        self.sys_resolve = list(pool.map(p.resolve_system, names))
        ok = [r for r in self.sys_resolve if r["ips"]]
        fake = any(p.ip_kind(ip) == "fake" for r in ok for ip in r["ips"])

        servers = list(DNS_SERVERS)
        if self.gw:
            servers.append(("Роутер", self.gw))

        def check(item):
            name, srv = item
            return (name, srv, p.dns_query(srv, "example.com", self.phys), p.dns_query(srv, "www.youtube.com", self.phys))

        self.dns_table = list(pool.map(check, servers))
        if not ok:
            self.node("dns", FAIL, "сломан")
            self.log(FAIL, "Системный DNS (%s) не отвечает" % (self.sys_dns or "?"))
            working = [n for n, _, c, _ in self.dns_table if c["ips"]]
            self.findings.append((FAIL, "Не работает DNS — сайты не открываются по именам",
                                  ("Пропиши DNS вручную: Системные настройки → Сеть → Подробнее → DNS → 1.1.1.1 и 77.88.8.8."
                                   + (" Напрямую отвечают: %s." % ", ".join(working) if working else ""))))
            return
        avg = sum(r["ms"] for r in ok) / len(ok)
        status = OK if len(ok) == len(names) and avg < 150 else WARN
        self.node("dns", status, "fake-ip" if fake else "%.0f мс" % avg)
        if fake:
            self.log(OK, "DNS отвечает подставными адресами 198.18.x.x — это режим fake-ip у VPN, всё нормально")
        else:
            self.log(status, "DNS %s отвечает за %.0f мс" % (self.sys_dns or "", avg))
        if status == WARN and not fake:
            self.findings.append((WARN, "DNS медленный (%.0f мс)" % avg,
                                  "Каждый новый сайт открывается с задержкой. Попробуй DNS 1.1.1.1 или 77.88.8.8."))
        filtered = [n for n, _, c, s in self.dns_table if c["ips"] and not s["ips"]]
        if filtered:
            self.log(WARN, "DNS %s не знает youtube.com — провайдер подменяет ответы" % ", ".join(filtered))
            self.findings.append((WARN, "Провайдер фильтрует DNS (%s)" % ", ".join(filtered),
                                  "Запросы к публичным DNS перехватываются и заблокированные домены «исчезают». "
                                  "Спасает DNS-over-HTTPS или VPN." if not self.vpn else
                                  "Запросы к публичным DNS перехватываются провайдером. Через VPN это не мешает."))

    def step_sites(self, pool):
        self.say("sites")
        self.node("sites", ACTIVE, "0/%d" % len(self.sites))

        def probe(item):
            name, host = item
            via = p.http_probe(host) if self.vpn else None
            ip = self._direct_ip(host)
            if ip:
                direct = p.http_probe(host, ip=ip, iface=self.phys, timeout=5)
            else:
                direct = {"host": host, "ip": None, "dns": None, "tcp": None, "tls": None, "http": None,
                          "status": None, "stage": "dns", "error": "домен не резолвится"}
            res = (name, host, via, direct)
            eff = via if self.vpn else direct
            with self.lock:
                self.site_results.append(res)
                done = len(self.site_results)
            self.node("sites", value="%d/%d" % (done, len(self.sites)))
            if eff["error"]:
                self.log(FAIL, "%s: %s" % (name, eff["error"]))
            return res

        list(pool.map(probe, self.sites))
        order = {h: i for i, (_, h) in enumerate(self.sites)}
        self.site_results.sort(key=lambda r: order[r[1]])
        eff = [(n, (v if self.vpn else d)) for n, _, v, d in self.site_results]
        bad = [n for n, r in eff if r["error"]]
        slow = [n for n, r in eff if not r["error"] and p.total_ms(r) > 2500]
        okn = len(eff) - len(bad)
        status = OK if not bad and not slow else (FAIL if len(bad) > len(eff) // 2 else WARN)
        self.node("sites", status, "%d/%d" % (okn, len(eff)))
        blocked_direct = [n for n, _, v, d in self.site_results if d["error"]]
        if bad:
            reasons = {}
            for n, r in eff:
                if r["error"]:
                    reasons.setdefault(reason_of(r), []).append(n)
            for why, names in reasons.items():
                if self.vpn:
                    tip = "Через VPN не открывается. Смени сервер в %s или проверь правила маршрутизации." % (
                        self.vpn_apps[0] if self.vpn_apps else "VPN")
                else:
                    tip = {
                        "dpi": "Похоже на блокировку через DPI — нужен VPN или обход блокировок.",
                        "ip": "Адрес сайта недоступен — блокировка по IP или проблема на стороне сайта.",
                        "dns": "DNS не отдаёт адрес — блокировка через DNS. Помогут DoH или VPN.",
                    }.get(why, "Попробуй ещё раз позже или через VPN.")
                self.findings.append((FAIL, "Не открывается: %s — %s" % (", ".join(names), REASON_TEXT[why]), tip))
        if slow:
            self.findings.append((WARN, "Медленно открываются: %s" % ", ".join(slow),
                                  "Сайты доступны, но отвечают дольше 2.5 с — перегружен канал или VPN-сервер."))
        if self.vpn and blocked_direct:
            saved = [n for n, _, v, d in self.site_results if d["error"] and v and not v["error"]]
            if saved:
                self.findings.append((OK, "VPN выручает: %s" % ", ".join(saved),
                                      "Напрямую эти сайты заблокированы, а через туннель работают."))
        unneeded = [n for n, _, v, d in self.site_results if self.vpn and not d["error"] and v and v["error"]]
        if unneeded:
            self.findings.append((WARN, "Напрямую работает, а через VPN нет: %s" % ", ".join(unneeded),
                                  "Добавь эти сайты в исключения VPN (direct), чтобы ходить к ним напрямую."))

    # ───────────────────────── итог ─────────────────────────

    def finish(self):
        score = 100
        for level, _, _ in self.findings:
            score -= {FAIL: 22, WARN: 7}.get(level, 0)
        if self.router_ping and self.router_ping.get("avg"):
            score -= min(8, max(0, (self.router_ping["avg"] - 5) / 3))
        # критические поломки ограничивают оценку сверху: без интернета здоровье не может быть 78
        caps = {"link": 0, "router": 10, "isp": 10, "dns": 25, "vpn": 30}
        for key, cap in caps.items():
            if self.nodes.get(key, {}).get("status") == FAIL:
                score = min(score, cap)
        if self.captive:
            score = min(score, 20)
        self.score = int(max(0, min(100, round(score)))) if not self.no_access else None
        fails = [f for f in self.findings if f[0] == FAIL]
        warns = [f for f in self.findings if f[0] == WARN]
        if fails:
            self.mood = "sad" if (self.score or 0) < 40 else "worried"
            self.headline = fails[0][1]
        elif warns:
            self.mood = "worried" if (self.score or 0) < 75 else "normal"
            self.headline = "В целом жить можно, но есть нюансы"
        else:
            self.mood = "happy"
            self.headline = "Сеть здорова, как краб в отпуске!"
        self.phrase = self.headline
        for key, n in self.nodes.items():
            if n["status"] in (PENDING, ACTIVE):
                n["status"] = SKIP
        self.done = True


# ───────────────────────── помощники ─────────────────────────

REASON_TEXT = {
    "dpi": "соединение рвётся на TLS (DPI)",
    "ip": "сервер недоступен по IP",
    "dns": "проблема с DNS",
    "cert": "подменён сертификат",
    "other": "ошибка соединения",
}


def reason_of(r):
    if r["stage"] == "dns":
        return "dns"
    if r["error"] == "чужой сертификат":
        return "cert"
    if r["stage"] == "tls" or r["stage"] == "http":
        return "dpi"
    if r["stage"] == "tcp":
        return "ip"
    return "other"


def signal_word(sig):
    if sig >= -55:
        return "отличный"
    if sig >= -67:
        return "хороший"
    if sig >= -75:
        return "слабый"
    return "очень слабый"


def short_org(org):
    if not org:
        return None
    for junk in (" customers", " Broadband", " LLC", " Ltd", " GmbH", " Inc.", " AS"):
        org = org.replace(junk, "")
    return org.strip()[:28]


COUNTRIES = {
    "RU": "Россия", "DE": "Германия", "NL": "Нидерланды", "FI": "Финляндия", "SE": "Швеция", "IS": "Исландия",
    "US": "США", "GB": "Великобритания", "FR": "Франция", "PL": "Польша", "LV": "Латвия", "EE": "Эстония",
    "LT": "Литва", "KZ": "Казахстан", "TR": "Турция", "AE": "ОАЭ", "JP": "Япония", "SG": "Сингапур",
    "CH": "Швейцария", "AT": "Австрия", "CZ": "Чехия", "GE": "Грузия", "AM": "Армения", "RS": "Сербия",
    "HK": "Гонконг", "CA": "Канада", "ES": "Испания", "IT": "Италия", "NO": "Норвегия", "MD": "Молдова",
}


def country_name(cc):
    return COUNTRIES.get(cc or "", cc or "?")


def flag(cc):
    return cc or ""
