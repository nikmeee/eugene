"""Диагностика по цепочке Mac → Wi-Fi → роутер → провайдер → VPN → DNS → сайты и выводы по ней."""

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


class Doctor:
    def __init__(self, sites=None, quick=False):
        self.sites = sites or SITES
        self.quick = quick
        self.lock = threading.Lock()
        self._wifi_future = None
        self.report = Report(started=time.perf_counter(), phrase=PHRASES["scan"][0], mood="think")
        for key, label in (("mac", "Mac"), ("link", "Сеть"), ("router", "Роутер"),
                           ("isp", "Провайдер"), ("dns", "DNS"), ("sites", "Сайты")):
            self.node(key, label=label)

    # ───────────────────────── служебное ─────────────────────────

    def snapshot(self):
        """Копия отчёта для экрана. Живой вид читает только её, не поля по ходу записи."""
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

    # ───────────────────────── шаги ─────────────────────────

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
                    self.node("vpn", SKIP, "нет канала")
                    self.log(SKIP, "VPN не проверяю: до интернета не дотянуться даже напрямую")
            self.step_dns(pool)
            if isp_up:
                self.step_sites(pool)
            else:
                self.node("sites", SKIP, "пропуск")
                self.log(SKIP, "Сайты не проверяю: за роутером нет интернета")
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
            # туннель есть, а физического маршрута не видно — пробуем Wi-Fi/ethernet напрямую
            for dev in ports:
                gw = p.sh(["ipconfig", "getoption", dev, "router"]).strip() if p.IS_MAC else ""
                if gw:
                    phys_routes = [(gw, dev)]
                    break
        self.node("mac", OK, p.sh(["hostname", "-s"]).strip()[:14] or "этот Mac")
        self._publish(sys_dns=sys_dns)
        if not phys_routes:
            self.log(FAIL, "Нет маршрута в интернет: Mac не подключён ни к Wi-Fi, ни к кабелю")
            self.node("link", FAIL, "нет связи")
            self.finding(FAIL, "Нет подключения к сети",
                         "Включи Wi-Fi или проверь кабель. Если Wi-Fi подключён — переподключись к сети.")
            return False
        gw, phys = phys_routes[0]
        port_name = ports.get(phys) or ("Wi-Fi" if phys == "en0" else phys)
        local_ip = p.iface_ip(phys)
        self._publish(vpn=vpn, vpn_iface=vpn_iface, vpn_apps=vpn_apps,
                      gw=gw, phys=phys, port_name=port_name, local_ip=local_ip)
        self.log(OK, "Интерфейс %s (%s), адрес %s" % (port_name, phys, local_ip or "?"))
        no_access = p.network_blocked(gw, phys)
        if no_access:
            self._publish(no_access=no_access)
            self.log(FAIL, "Сокеты отклоняются ещё до отправки пакетов: %s" % no_access)
            self.node("link", OK, phys, label="Wi-Fi" if "wi-fi" in (port_name or "").lower() else "Кабель")
            self.node("router", FAIL, "нет доступа")
            self.finding(FAIL, "У этого терминала нет доступа к сети",
                         "Система не даёт программе открывать соединения — роутер тут ни при чём. "
                         "Запусти eugene в обычном Terminal.app или iTerm. Если и там так — проверь "
                         "фаервол (Little Snitch, LuLu) или профили управления устройством.")
            return False
        if vpn:
            self.node("vpn", label="VPN")
            with self.lock:
                order = self.report.node_order
                order.remove("vpn")
                order.insert(order.index("isp") + 1, "vpn")
            app = vpn_apps[0] if vpn_apps else "VPN"
            self.log(OK, "Трафик идёт через туннель %s — похоже, это %s" % (vpn_iface, app))
        return True

    def step_link(self):
        port_name = self.report.port_name
        phys = self.report.phys
        is_wifi = "wi-fi" in (port_name or "").lower() or "airport" in (port_name or "").lower()
        self.node("link", ACTIVE, label="Wi-Fi" if is_wifi else "Кабель")
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
            self.log(OK, "Wi-Fi подключён")
            return
        sig = wifi["signal"]
        snr = sig - wifi["noise"] if wifi.get("noise") is not None else None
        band = "5 ГГц" if "5GHz" in (wifi.get("channel") or "") else ("6 ГГц" if "6GHz" in (wifi.get("channel") or "") else "2.4 ГГц")
        if sig >= -67:
            self.node("link", OK, "%d dBm" % sig)
            self.log(OK, "Wi-Fi %s: сигнал %d dBm, %s — %s" % (band, sig, wifi.get("phy") or "", signal_word(sig)))
        elif sig >= -75:
            self.node("link", WARN, "%d dBm" % sig)
            self.log(WARN, "Wi-Fi сигнал слабоват: %d dBm" % sig)
            self.finding(WARN, "Слабый сигнал Wi-Fi (%d dBm)" % sig,
                         "Подойди ближе к роутеру или убери преграды; для стабильности лучше −67 dBm и выше.")
        else:
            self.node("link", FAIL, "%d dBm" % sig)
            self.log(FAIL, "Wi-Fi сигнал очень слабый: %d dBm" % sig)
            self.finding(FAIL, "Очень слабый Wi-Fi (%d dBm)" % sig,
                         "Связь будет рваться. Подойди к роутеру, поставь репитер или mesh.")
        if band == "2.4 ГГц" and sig >= -67:
            self.finding(WARN, "Wi-Fi на 2.4 ГГц",
                         "Этот диапазон медленнее и шумнее. Если роутер умеет 5 ГГц — подключись к нему.")
        if snr is not None and snr < 20:
            self.finding(WARN, "Много помех в эфире (SNR %d dB)" % snr,
                         "Смени канал Wi-Fi в настройках роутера на менее загруженный.")

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
            self.node("router", FAIL, "молчит")
            self.log(FAIL, "Роутер %s не отвечает на ping" % gw)
            self.finding(FAIL, "Роутер не отвечает",
                         "Проверь, что роутер включён; перезагрузи его (выключи на 10 секунд).")
            # некоторые роутеры просто глушат ping — проверим, есть ли интернет дальше
            probe = p.ping("1.1.1.1", count=3, iface=phys)
            if probe["recv"]:
                self._set_finding(-1, (WARN, "Роутер не отвечает на ping",
                                       "Интернет при этом есть — скорее всего, роутер просто игнорирует ping."))
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
            self.finding(status, "Нестабильная связь с роутером (потери %.0f%%, %.0f мс)" % (r["loss"], r["avg"]),
                         "Проблема между Mac и роутером: обычно это Wi-Fi — помехи, расстояние или перегруженный роутер.")
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
            self.node("isp", FAIL, "нет связи")
            self.log(FAIL, "За роутером тишина: ни один сервер в интернете не отвечает")
            self.finding(FAIL, "Нет интернета за роутером",
                         "Роутер жив, но наружу не выходит. Перезагрузи роутер; не помогло — звони провайдеру "
                         "(проверь и баланс).")
            return False
        best = min(r["avg"] for r in alive) if alive else None
        loss = max(r["loss"] for r in alive) if alive else 0
        status = OK
        if best is not None and (best > 80 or loss > 10):
            status = FAIL if loss > 20 else WARN
        elif loss > 0 or (best is not None and best > 40):
            status = WARN
        self.node("isp", status, ("%.0f мс" % best) if best is not None else "без ping")
        self.log(status, "Провайдер %s: до 1.1.1.1 %s, потери %.0f%%" % (
            short_org(org) or "?", ("%.0f мс" % pings[0][1]["avg"]) if pings[0][1]["avg"] else "—", loss))
        if status != OK and best is not None:
            self.finding(status, "Канал провайдера нестабилен (%.0f мс, потери до %.0f%%)" % (best, loss),
                         "Если роутер при этом отвечает быстро — проблема у провайдера. Перезагрузи роутер, "
                         "а если повторяется — пиши в поддержку.")
        if captive:
            self.finding(FAIL, "Сеть требует авторизации",
                         "Это сеть с входом через браузер (кафе, отель, метро). Открой любой сайт по http и войди.")
            self.log(FAIL, "Обнаружен captive-портал — нужна авторизация")
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
            self.node("vpn", FAIL, "не везёт")
            self.log(FAIL, "%s включён, но трафик через туннель не проходит" % app)
            self.finding(FAIL, "VPN не пропускает трафик",
                         "%s поднял туннель, но дальше тишина. Переключи сервер или перезапусти VPN." % app)
            return
        cc = (meta or {}).get("country")
        status = OK if (vpn_rtt or 0) < 250 else WARN
        self.node("vpn", status, "%s · %s" % (flag(cc), ("%.0f мс" % vpn_rtt) if vpn_rtt else ""))
        self.log(status, "%s → выход: %s (%s), задержка %s" % (
            app, country_name(cc), short_org((meta or {}).get("asOrganization")) or "?",
            ("%.0f мс" % vpn_rtt) if vpn_rtt else "?"))
        if status == WARN:
            self.finding(WARN, "Медленный VPN-сервер (%.0f мс)" % vpn_rtt,
                         "Сервер далеко или перегружен. Выбери сервер поближе — Финляндия, Нидерланды, Германия.")

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
                    "status": None, "stage": "dns", "error": "домен не резолвится"}
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
            servers.append(("Роутер", self.report.gw))

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
            self.node("dns", FAIL, "сломан")
            self.log(FAIL, "Системный DNS (%s) не отвечает" % (sys_dns or "?"))
            working = [n for n, _, c, _ in table if c["ips"]]
            self.finding(FAIL, "Не работает DNS — сайты не открываются по именам",
                         ("Пропиши DNS вручную: Системные настройки → Сеть → Подробнее → DNS → 1.1.1.1 и 77.88.8.8."
                          + (" Напрямую отвечают: %s." % ", ".join(working) if working else "")))
            return
        avg = sum(r["ms"] for r in ok) / len(ok)
        status = OK if len(ok) == len(names) and avg < 150 else WARN
        self.node("dns", status, "fake-ip" if fake else "%.0f мс" % avg)
        if fake:
            self.log(OK, "DNS отвечает подставными адресами 198.18.x.x — это режим fake-ip у VPN, всё нормально")
        else:
            self.log(status, "DNS %s отвечает за %.0f мс" % (sys_dns or "", avg))
        if status == WARN and not fake:
            self.finding(WARN, "DNS медленный (%.0f мс)" % avg,
                         "Каждый новый сайт открывается с задержкой. Попробуй DNS 1.1.1.1 или 77.88.8.8.")
        filtered = [n for n, _, c, s in table if c["ips"] and not s["ips"]]
        if filtered:
            self.log(WARN, "DNS %s не знает youtube.com — провайдер подменяет ответы" % ", ".join(filtered))
            via = "Запросы к публичным DNS перехватываются и заблокированные домены «исчезают». Спасает DNS-over-HTTPS или VPN."
            if self.report.vpn:
                via = "Запросы к публичным DNS перехватываются провайдером. Через VPN это не мешает."
            self.finding(WARN, "Провайдер фильтрует DNS (%s)" % ", ".join(filtered), via)

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
                    tip = "Через VPN не открывается. Смени сервер в %s или проверь правила маршрутизации." % vpn_app
                else:
                    tip = {
                        "dpi": "Похоже на блокировку через DPI — нужен VPN или обход блокировок.",
                        "ip": "Адрес сайта недоступен — блокировка по IP или проблема на стороне сайта.",
                        "dns": "DNS не отдаёт адрес — блокировка через DNS. Помогут DoH или VPN.",
                    }.get(why, "Попробуй ещё раз позже или через VPN.")
                self.finding(FAIL, "Не открывается: %s — %s" % (", ".join(names), REASON_TEXT[why]), tip)
        if slow:
            self.finding(WARN, "Медленно открываются: %s" % ", ".join(slow),
                         "Сайты доступны, но отвечают дольше 2.5 с — перегружен канал или VPN-сервер.")
        blocked_direct = [n for n, _, v, d in results if d["error"]]
        if use_vpn and blocked_direct:
            saved = [n for n, _, v, d in results if d["error"] and v and not v["error"]]
            if saved:
                self.finding(OK, "VPN выручает: %s" % ", ".join(saved),
                             "Напрямую эти сайты заблокированы, а через туннель работают.")
        unneeded = [n for n, _, v, d in results if use_vpn and not d["error"] and v and v["error"]]
        if unneeded:
            self.finding(WARN, "Напрямую работает, а через VPN нет: %s" % ", ".join(unneeded),
                         "Добавь эти сайты в исключения VPN (direct), чтобы ходить к ним напрямую.")

    # ───────────────────────── итог ─────────────────────────

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
                r.headline = "В целом жить можно, но есть нюансы"
            else:
                r.mood = "happy"
                r.headline = "Сеть здорова, как краб в отпуске!"
            r.phrase = r.headline
            for n in r.nodes.values():
                if n["status"] in (PENDING, ACTIVE):
                    n["status"] = SKIP
            r.done = True


# ───────────────────────── помощники ─────────────────────────

REASON_TEXT = {
    "dpi": "соединение рвётся на TLS (DPI)",
    "ip": "сервер недоступен по IP",
    "dns": "проблема с DNS",
    "cert": "подменён сертификат",
    "other": "ошибка соединения",
}


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
