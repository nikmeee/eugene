"""🦀 Eugene — краб, который выясняет, почему не работает интернет."""

import argparse
import json
import sys
import threading
import time

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from . import __version__
from . import probes as p
from .crab import crab_text
from .doctor import ACTIVE, FAIL, OK, PENDING, SKIP, WARN, Doctor, country_name, reason_of, short_org

CORAL = "#ff6a4d"
SEA = "#5cc8ff"
TITLE = ["#ff6a4d", "#ffa36b", "#ffd58a", "#5cc8ff"]
COLORS = {OK: "#3ddc97", WARN: "#ffcf5c", FAIL: "#ff5c7a", ACTIVE: SEA, PENDING: "grey35", SKIP: "grey35"}
DIM = "grey50"
FAINT = "grey23"
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
BLOCKS = "▁▂▃▄▅▆▇█"
PHASES = {"dns": "#b388ff", "tcp": "#3d7bff", "tls": SEA, "http": "#3ddc97"}

# ───────────────────────────── мелочи ──────────────────────────────


def _rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))


def grad(stops, t):
    t = max(0.0, min(1.0, t))
    n = len(stops) - 1
    i = min(int(t * n), n - 1)
    lt = t * n - i
    a, b = _rgb(stops[i]), _rgb(stops[i + 1])
    return "#%02x%02x%02x" % tuple(int(a[k] + (b[k] - a[k]) * lt) for k in range(3))


def gradient_text(s, stops, bold=True):
    t = Text()
    n = max(1, len(s) - 1)
    for i, ch in enumerate(s):
        t.append(ch, style=("bold " if bold else "") + grad(stops, i / n))
    return t


def spin():
    return SPINNER[int(time.time() * 12) % len(SPINNER)]


def icon(level):
    return {OK: "✔", WARN: "▲", FAIL: "✖", ACTIVE: spin(), PENDING: "○", SKIP: "○"}.get(level, "•")


def ms(v):
    if v is None:
        return "—"
    return "%.1f мс" % v if v < 10 else "%.0f мс" % v


def mask_ip(ip):
    if not ip:
        return "?"
    return ".".join(ip.split(".")[:3]) + ".•••" if "." in ip else ":".join(ip.split(":")[:3]) + ":••••"


def sparkline(values, width=10, color=SEA):
    vals = values[-width:]
    t = Text()
    if not vals:
        return t
    lo, hi = min(vals), max(vals)
    for v in vals:
        k = 0 if hi - lo < 0.5 else int((v - lo) / (hi - lo) * (len(BLOCKS) - 1))
        t.append(BLOCKS[k], style=color)
    return t


FONT = {
    "0": ["███", "█ █", "█ █", "█ █", "███"], "1": ["██ ", " █ ", " █ ", " █ ", "███"],
    "2": ["███", "  █", "███", "█  ", "███"], "3": ["███", "  █", "███", "  █", "███"],
    "4": ["█ █", "█ █", "███", "  █", "  █"], "5": ["███", "█  ", "███", "  █", "███"],
    "6": ["███", "█  ", "███", "█ █", "███"], "7": ["███", "  █", "  █", "  █", "  █"],
    "8": ["███", "█ █", "███", "█ █", "███"], "9": ["███", "█ █", "███", "  █", "███"],
    "?": ["███", "  █", " ██", "   ", " █ "],
}


def big_number(n, color_stops):
    s = str(n)
    rows = [" ".join(FONT[ch][r] for ch in s) for r in range(5)]
    w = max(1, len(rows[0]) - 1)
    out = Text()
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            out.append(ch, style=grad(color_stops, c / w) if ch != " " else None)
        if r < 4:
            out.append("\n")
    return out


def score_stops(score):
    if score >= 85:
        return ["#3ddc97", SEA]
    if score >= 60:
        return ["#ffcf5c", "#3ddc97"]
    if score >= 35:
        return ["#ff8a3d", "#ffcf5c"]
    return ["#ff5c7a", "#ff8a3d"]


# ───────────────────────────── блоки ───────────────────────────────


def header():
    t = Text(" ")
    t.append_text(gradient_text("E U G E N E", TITLE))
    t.append("   сетевой доктор", style=DIM)
    t.append("  v%s" % __version__, style=FAINT)
    return t


def bubble(lines, border=CORAL, width=None):
    body = Text()
    for i, (text, style) in enumerate(lines):
        body.append(text, style=style)
        if i < len(lines) - 1:
            body.append("\n")
    return Panel(body, box=box.ROUNDED, border_style=border, padding=(0, 2), width=width)


def crab_scene(doc, lines, extra=None, border=CORAL):
    frame = int(time.time() * 3) if not doc.done else 0
    g = Table.grid(padding=(0, 0))
    g.add_column(no_wrap=True)
    g.add_column(no_wrap=True, vertical="middle")
    g.add_column(ratio=1, vertical="middle")
    tail = Text("◀", style=border)
    row = [crab_text(doc.mood, frame), tail, bubble(lines, border)]
    if extra is not None:
        g.add_column(vertical="middle")
        row.append(extra)
    g.add_row(*row)
    return g


def chain(doc, width):
    keys = list(doc.node_order)
    nodes = [doc.nodes[k] for k in keys]
    n = len(nodes)
    cell = width // n
    centers = [cell * i + cell // 2 for i in range(n)]
    rail = Text()
    t = time.time()
    for i in range(n):
        st = nodes[i]["status"]
        # кусок рельса до узла
        start = 0 if i == 0 else centers[i - 1] + 1
        seg_len = centers[i] - start
        if i > 0:
            if st in (OK, WARN, FAIL):
                for _ in range(seg_len):
                    rail.append("━", style=COLORS[st])
            elif st == ACTIVE:
                pos = int(t * 14) % max(1, seg_len)
                for j in range(seg_len):
                    rail.append("━", style=SEA if abs(j - pos) <= 1 else "grey30")
            else:
                rail.append("┄" * seg_len, style=FAINT)
        else:
            rail.append(" " * seg_len)
        rail.append("◉" if st == OK else icon(st), style="bold " + COLORS.get(st, DIM))
    labels, values = Text(), Text()
    for i, nd in enumerate(nodes):
        st = nd["status"]
        labels.append(nd["label"][:cell - 1].center(cell), style=("bold " + COLORS[st]) if st != PENDING else DIM)
        values.append(str(nd["value"])[:cell - 1].center(cell), style=DIM if st != FAIL else COLORS[FAIL])
    return Group(rail, labels, values)


def event_log(doc, n):
    out = Text()
    evs = doc.events[-n:]
    for i, (lvl, text) in enumerate(evs):
        out.append("  %s " % icon(lvl), style=COLORS.get(lvl, DIM))
        out.append(text, style=None if lvl == OK else COLORS.get(lvl))
        if i < len(evs) - 1:
            out.append("\n")
    if not doc.done:
        out.append(("\n" if evs else "") + "  %s " % spin(), style=SEA)
        out.append("…", style=DIM)
    return out


def live_view(doc, console):
    width = min(console.width, 100)
    inner = width - 4
    elapsed = time.perf_counter() - doc.started
    lines = [(doc.phrase, "bold"), ("", None), ("%.1f с · проверено узлов: %d из %d" % (
        elapsed, sum(1 for k in doc.node_order if doc.nodes[k]["status"] in (OK, WARN, FAIL)), len(doc.node_order)), DIM)]
    log_n = max(3, min(8, console.height - 21))
    parts = [header(), Text(""), crab_scene(doc, lines), Text(""), chain(doc, inner), Text(""), event_log(doc, log_n)]
    return Panel(Group(*parts), box=box.HEAVY, border_style=FAINT, width=width, padding=(0, 1))


# ─────────────────────────── итоговый отчёт ────────────────────────


def kv(rows):
    t = Table.grid(padding=(0, 2))
    t.add_column(style=DIM, no_wrap=True)
    t.add_column()
    for k, v in rows:
        t.add_row(k, v if isinstance(v, Text) else Text(str(v)))
    return t


def signal_bars(sig):
    lvl = 5 if sig >= -55 else 4 if sig >= -62 else 3 if sig >= -67 else 2 if sig >= -75 else 1
    col = COLORS[OK] if lvl >= 3 else COLORS[WARN] if lvl == 2 else COLORS[FAIL]
    t = Text()
    for i, ch in enumerate("▂▃▅▆█"):
        t.append(ch, style=col if i < lvl else FAINT)
    return t


def pretty_channel(ch):
    if not ch:
        return "?"
    return ch.replace("GHz", " ГГц").replace("MHz", " МГц").replace("(", "· ").replace(")", "").replace(",", " ·")


def ping_cell(r):
    if not r or not r["recv"]:
        return Text("не отвечает", style=COLORS[FAIL])
    lvl = OK if r["loss"] == 0 and r["avg"] < 40 else WARN if r["loss"] < 20 else FAIL
    t = Text(ms(r["avg"]).rjust(7), style="bold " + COLORS[lvl])
    t.append("  ")
    t.append_text(sparkline(r["times"], 10, COLORS[lvl]))
    t.append("  потери %.0f%%" % r["loss"], style=DIM if r["loss"] == 0 else COLORS[WARN])
    return t


def local_block(doc):
    rows = [("Интерфейс", "%s (%s) · %s" % (doc.port_name, doc.phys, doc.local_ip or "?"))]
    w = doc.wifi
    if w and w.get("signal") is not None:
        s = signal_bars(w["signal"])
        s.append("  %d dBm" % w["signal"], style="bold")
        if w.get("noise") is not None:
            s.append(" · SNR %d dB" % (w["signal"] - w["noise"]), style=DIM)
        rows.append(("Сигнал", s))
        if w.get("ssid"):
            rows.append(("Сеть", w["ssid"]))
        rows.append(("Канал", pretty_channel(w.get("channel"))))
        std = Text(w.get("phy") or "?")
        if w.get("rate"):
            std.append(" · %s Мбит/с" % w["rate"], style=DIM)
        if w.get("security"):
            std.append(" · %s" % w["security"].split("_")[0].upper(), style=DIM)
        rows.append(("Стандарт", std))
    if doc.gw:
        rows.append(("Роутер", "%s · %s" % (doc.router_brand, doc.gw) if doc.router_brand else doc.gw))
    if doc.router_ping:
        rows.append(("До роутера", ping_cell(doc.router_ping)))
    return kv(rows)


def internet_block(doc):
    rows = []
    m = doc.meta_direct or {}
    if m:
        rows.append(("Провайдер", "%s (AS%s)" % (short_org(m.get("asOrganization")) or "?", m.get("asn", "?"))))
        rows.append(("Внешний IP", "%s · %s, %s" % (mask_ip(m.get("clientIp")), m.get("city", "?"), m.get("country", "?"))))
    if doc.vpn:
        v = doc.meta_vpn or {}
        t = Text(doc.vpn_apps[0] if doc.vpn_apps else doc.vpn_iface, style="bold " + SEA)
        if v:
            t.append(" → %s" % country_name(v.get("country")), style=None)
            t.append(" · %s" % (short_org(v.get("asOrganization")) or "?"), style=DIM)
        rows.append(("VPN", t))
        if doc.vpn_rtt:
            rows.append(("Через VPN", Text(ms(doc.vpn_rtt).rjust(7), style="bold " + (COLORS[OK] if doc.vpn_rtt < 150 else COLORS[WARN]))))
    for name, r in doc.isp_pings:
        rows.append(("%s" % r["host"], ping_cell(r)))
    rows.append(("IPv6", Text("есть", style=COLORS[OK]) if doc.ipv6 else Text("нет", style=DIM)))
    if doc.captive is not None:
        rows.append(("Вход в сеть", Text("нужна авторизация!", style=COLORS[FAIL]) if doc.captive else Text("не нужен", style=DIM)))
    return kv(rows)


def dns_cell(d, sensitive=False):
    if d["error"]:
        return Text(d["error"], style=COLORS[FAIL])
    if not d["ips"]:
        word = "NXDOMAIN" if d["rcode"] == 3 else "пусто"
        return Text("%s · %s" % (word, ms(d["ms"])), style=COLORS[WARN])
    lvl = OK if d["ms"] < 80 else WARN
    return Text(ms(d["ms"]), style=COLORS[lvl])


def dns_block(doc):
    t = Table(box=box.SIMPLE_HEAD, header_style=DIM, padding=(0, 2), show_edge=False)
    t.add_column("Сервер")
    t.add_column("example.com")
    t.add_column("youtube.com")
    for name, srv, ctrl, sens in doc.dns_table:
        t.add_row(Text(name) + Text("  " + srv, style=DIM), dns_cell(ctrl), dns_cell(sens, True))
    sysline = Text("  Системный DNS: ", style=DIM)
    sysline.append(doc.sys_dns or "?", style="bold")
    fake = any(p.ip_kind(ip) == "fake" for r in doc.sys_resolve for ip in r["ips"])
    if fake:
        sysline.append("  — fake-ip от VPN: имена резолвит сам туннель", style=DIM)
    elif doc.sys_resolve:
        oks = [r["ms"] for r in doc.sys_resolve if r["ms"]]
        if oks:
            sysline.append("  · %s в среднем" % ms(sum(oks) / len(oks)), style=DIM)
    return Group(sysline, t)


def waterfall(r, scale=1500.0, width=16):
    t = Text()
    used = 0
    for k in ("dns", "tcp", "tls", "http"):
        v = r.get(k)
        if not v:
            continue
        n = max(1, int(round(min(v, scale) / scale * width)))
        n = min(n, width - used)
        if n <= 0:
            break
        t.append("▬" * n, style=PHASES[k])
        used += n
    t.append(" " * (width - used))
    return t


def site_cell(r):
    if r is None:
        return Text("—", style=DIM)
    if r["error"]:
        t = Text("✖ ", style=COLORS[FAIL])
        t.append(r["error"], style=COLORS[FAIL])
        return t
    total = p.total_ms(r)
    lvl = OK if total < 1200 else WARN
    t = waterfall(r)
    t.append(" %6s" % ms(total), style="bold " + COLORS[lvl])
    if r["status"] and r["status"] >= 400:
        t.append(" HTTP %d" % r["status"], style=DIM)
    return t


def sites_block(doc):
    t = Table(box=box.SIMPLE_HEAD, header_style=DIM, padding=(0, 2), show_edge=False)
    t.add_column("Сайт", no_wrap=True)
    if doc.vpn:
        t.add_column("через VPN", no_wrap=True)
    t.add_column("напрямую" if doc.vpn else "доступ", no_wrap=True)
    for name, host, via, direct in doc.site_results:
        eff = via if doc.vpn else direct
        mark = Text("✔ " if not eff["error"] else "✖ ", style=COLORS[OK] if not eff["error"] else COLORS[FAIL])
        mark.append(name, style="bold" if not eff["error"] else COLORS[FAIL])
        row = [mark]
        if doc.vpn:
            row.append(site_cell(via))
        row.append(site_cell(direct))
        t.add_row(*row)
    legend = Text("  ")
    for k, label in (("dns", "DNS"), ("tcp", "TCP"), ("tls", "TLS"), ("http", "ответ")):
        legend.append("▬ ", style=PHASES[k])
        legend.append(label + "   ", style=DIM)
    return Group(t, legend)


def findings_block(doc):
    items = sorted(doc.findings, key=lambda f: {FAIL: 0, WARN: 1, OK: 2}.get(f[0], 3))
    t = Table.grid(padding=(0, 1))
    t.add_column(no_wrap=True)
    t.add_column(ratio=1)
    if not items:
        t.add_row(Text(" ✔", style=COLORS[OK]),
                  Text("Проблем не нашёл. Если что-то тормозит — дело, скорее всего, в самом сайте или приложении."))
        return t
    for lvl, title, tip in items:
        body = Text()
        body.append(title, style="bold " + (COLORS[lvl] if lvl != OK else ""))
        body.append("\n" + tip, style=DIM)
        t.add_row(Text(" " + icon(lvl), style=COLORS[lvl]), body)
    return t


def section(title):
    return Rule(Text(" %s " % title, style="bold " + DIM), style=FAINT, align="left")


def final_view(doc, console):
    width = min(console.width, 100)
    st = score_stops(doc.score) if doc.score is not None else ["#7f7f7f", "#b3b3b3"]
    sub = {"happy": "Можно спокойно сидеть в интернете 🌊", "normal": "Есть пара мелочей — смотри ниже",
           "worried": "Кое-что не так — разбор ниже", "sad": "Дело плохо — но я подскажу, что делать"}[doc.mood]
    score = Table.grid()
    score.add_column(justify="center")
    score.add_row(big_number(doc.score if doc.score is not None else "?", st))
    score.add_row(Text("здоровье сети" if doc.score is not None else "не измерить", style=DIM))
    border = {"happy": COLORS[OK], "normal": SEA, "worried": COLORS[WARN], "sad": COLORS[FAIL]}[doc.mood]
    scene = crab_scene(doc, [(doc.headline, "bold"), ("", None), (sub, DIM)], extra=score, border=border)

    parts = [header(), Text(""), scene, Text(""), chain(doc, width - 4)]
    if doc.phys:
        cols = Table.grid(expand=True, padding=(0, 3))
        cols.add_column(ratio=1)
        cols.add_column(ratio=1)
        cols.add_row(Group(section("ЛОКАЛЬНАЯ СЕТЬ"), local_block(doc)),
                     Group(section("ИНТЕРНЕТ"), internet_block(doc)) if doc.isp_pings else Text(""))
        parts += [Text(""), cols]
    if doc.dns_table:
        parts += [Text(""), section("DNS"), dns_block(doc)]
    if doc.site_results:
        parts += [Text(""), section("САЙТЫ"), sites_block(doc)]
    parts += [Text(""), section("ДИАГНОЗ"), findings_block(doc)]
    return Panel(Group(*parts), box=box.HEAVY, border_style=FAINT, width=width, padding=(0, 1),
                 subtitle=Text(" проверено за %.1f с " % (time.perf_counter() - doc.started), style=FAINT))


# ─────────────────────────────── JSON ──────────────────────────────


def to_json(doc):
    def site(r):
        if r is None:
            return None
        return {"ok": not r["error"], "error": r["error"], "stage": r["stage"], "status": r["status"],
                "ms": round(p.total_ms(r), 1), "reason": reason_of(r) if r["error"] else None}

    return {
        "score": doc.score,
        "headline": doc.headline,
        "interface": doc.phys, "router": doc.gw, "router_brand": doc.router_brand,
        "wifi": doc.wifi,
        "router_ping": doc.router_ping and {k: doc.router_ping[k] for k in ("avg", "jitter", "loss")},
        "isp": (doc.meta_direct or {}).get("asOrganization"),
        "vpn": {"active": doc.vpn, "apps": doc.vpn_apps, "exit_country": (doc.meta_vpn or {}).get("country"),
                "rtt_ms": doc.vpn_rtt} if doc.vpn else {"active": False},
        "pings": {r["host"]: {k: r[k] for k in ("avg", "jitter", "loss")} for _, r in doc.isp_pings},
        "dns": {"system": doc.sys_dns},
        "sites": {name: {"via_vpn": site(v), "direct": site(d)} for name, _, v, d in doc.site_results},
        "findings": [{"level": l, "title": t, "tip": tip} for l, t, tip in doc.findings],
    }


# ─────────────────────────────── main ──────────────────────────────


def main():
    ap = argparse.ArgumentParser(prog="eugene", description="Краб Юджин выясняет, почему не работает интернет")
    ap.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("-q", "--quick", action="store_true", help="быстрая проверка (меньше пингов)")
    ap.add_argument("-s", "--site", action="append", metavar="ДОМЕН", help="проверить ещё сайт (можно несколько раз)")
    ap.add_argument("--json", action="store_true", help="вывести результат в JSON")
    args = ap.parse_args()

    from .doctor import SITES
    sites = list(SITES) + [(h, h) for h in (args.site or [])]
    doc = Doctor(sites=sites, quick=args.quick)
    console = Console()

    try:
        if args.json:
            doc.run()
            print(json.dumps(to_json(doc), ensure_ascii=False, indent=2))
            return 0
        worker = threading.Thread(target=doc.run, daemon=True)
        worker.start()
        with Live(get_renderable=lambda: live_view(doc, console), console=console,
                  refresh_per_second=12, transient=True):
            while worker.is_alive():
                worker.join(0.1)
        console.print(final_view(doc, console))
    except KeyboardInterrupt:
        console.print("\n  [grey50]🦀 Юджин уполз. Прервано.[/]")
        return 130
    return 0 if doc.score is None or doc.score >= 60 else 1


def cli():
    sys.exit(main())


if __name__ == "__main__":
    cli()
