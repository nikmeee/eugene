"""User-facing language. English is the default; Russian follows the Mac language."""

import os
import re
import subprocess
import sys

language = "en"

_STRINGS = {
    "phrase.scan.1": ("Looking around the burrow for network interfaces", "Осматриваюсь в норке… ищу сетевые интерфейсы"),
    "phrase.scan.2": ("Antennae up — what kind of network is this?", "Высовываю стебельки — что тут у нас за сеть?"),
    "phrase.link.1": ("Poking the Wi-Fi with a claw…", "Щупаю Wi-Fi клешнёй…"),
    "phrase.link.2": ("Sniffing the airwaves…", "Ловлю радиоволны усиками…"),
    "phrase.link_eth": ("Checking the cable — is it seated?", "Проверяю кабель — крепко держится?"),
    "phrase.router.1": ("Knock knock, router", "Стучусь в роутер: тук-тук!"),
    "phrase.router.2": ("Tapping the router…", "Щёлк-щёлк по роутеру…"),
    "phrase.isp.1": ("Sidling toward the ISP…", "Ползу боком к провайдеру…"),
    "phrase.isp.2": ("Peeking past the router — is the internet there?", "Выглядываю за роутер — есть там интернет?"),
    "phrase.vpn.1": ("Diving into the VPN tunnel… blub", "Ныряю в VPN-туннель… буль!"),
    "phrase.vpn.2": ("Swimming toward the VPN exit…", "Плыву по туннелю к выходу VPN…"),
    "phrase.dns.1": ("Sniffing the DNS…", "Принюхиваюсь к DNS…"),
    "phrase.dns.2": ("Asking the DNS servers for directions…", "Спрашиваю у DNS-серверов дорогу…"),
    "phrase.sites.1": ("Clicking through sites with a claw…", "Щёлкаю по сайтам клешнёй…"),
    "phrase.sites.2": ("Walking the usual sites, one by one…", "Обхожу любимые сайты по очереди…"),
    "node.link": ("Link", "Сеть"),
    "node.router": ("Router", "Роутер"),
    "node.isp": ("ISP", "Провайдер"),
    "node.sites": ("Sites", "Сайты"),
    "node.cable": ("Cable", "Кабель"),
    "value.no_link": ("no link", "нет связи"),
    "value.no_channel": ("no link", "нет канала"),
    "value.skipped": ("skipped", "пропуск"),
    "value.no_access": ("no access", "нет доступа"),
    "value.silent": ("silent", "молчит"),
    "value.no_ping": ("no ping", "без ping"),
    "value.no_route": ("no route", "не везёт"),
    "value.broken": ("broken", "сломан"),
    "value.this_mac": ("this Mac", "этот Mac"),
    "log.skip_vpn": ("Skipping VPN: the internet is unreachable even directly", "VPN не проверяю: до интернета не дотянуться даже напрямую"),
    "log.skip_sites": ("Skipping sites: there is no internet beyond the router", "Сайты не проверяю: за роутером нет интернета"),
    "log.no_route": ("No route to the internet: the Mac is not on Wi-Fi or a cable", "Нет маршрута в интернет: Mac не подключён ни к Wi-Fi, ни к кабелю"),
    "find.no_network": ("No network connection", "Нет подключения к сети"),
    "tip.no_network": ("Turn on Wi-Fi or check the cable. If Wi-Fi is connected, reconnect to the network.", "Включи Wi-Fi или проверь кабель. Если Wi-Fi подключён — переподключись к сети."),
    "log.iface": ("Interface {port} ({phys}), address {ip}", "Интерфейс {port} ({phys}), адрес {ip}"),
    "log.no_access": ("Sockets are rejected before any packet is sent: {reason}", "Сокеты отклоняются ещё до отправки пакетов: {reason}"),
    "find.sandbox": ("This terminal has no network access", "У этого терминала нет доступа к сети"),
    "tip.sandbox": ("The system will not let the program open connections — the router is not the problem. Run eugene in Terminal.app or iTerm. If it still fails, check a firewall (Little Snitch, LuLu) or device-management profiles.", "Система не даёт программе открывать соединения — роутер тут ни при чём. Запусти eugene в обычном Terminal.app или iTerm. Если и там так — проверь фаервол (Little Snitch, LuLu) или профили управления устройством."),
    "log.tunnel": ("Traffic goes through tunnel {iface} — looks like {app}", "Трафик идёт через туннель {iface} — похоже, это {app}"),
    "log.wifi_on": ("Wi-Fi is connected", "Wi-Fi подключён"),
    "log.wifi_ok": ("Wi-Fi {band}: signal {sig} dBm, {phy} — {word}", "Wi-Fi {band}: сигнал {sig} dBm, {phy} — {word}"),
    "log.wifi_weak": ("Wi-Fi signal is a bit weak: {sig} dBm", "Wi-Fi сигнал слабоват: {sig} dBm"),
    "find.wifi_weak": ("Weak Wi-Fi signal ({sig} dBm)", "Слабый сигнал Wi-Fi ({sig} dBm)"),
    "tip.wifi_weak": ("Move closer to the router or clear obstructions. −67 dBm or stronger is more stable.", "Подойди ближе к роутеру или убери преграды; для стабильности лучше −67 dBm и выше."),
    "log.wifi_bad": ("Wi-Fi signal is very weak: {sig} dBm", "Wi-Fi сигнал очень слабый: {sig} dBm"),
    "find.wifi_bad": ("Very weak Wi-Fi ({sig} dBm)", "Очень слабый Wi-Fi ({sig} dBm)"),
    "tip.wifi_bad": ("The link will drop. Move closer to the router, or add a repeater or mesh.", "Связь будет рваться. Подойди к роутеру, поставь репитер или mesh."),
    "find.band": ("Wi-Fi is on 2.4 GHz", "Wi-Fi на 2.4 ГГц"),
    "tip.band": ("This band is slower and noisier. If the router offers 5 GHz, use that.", "Этот диапазон медленнее и шумнее. Если роутер умеет 5 ГГц — подключись к нему."),
    "find.snr": ("A lot of radio noise (SNR {snr} dB)", "Много помех в эфире (SNR {snr} dB)"),
    "tip.snr": ("Change the Wi-Fi channel in the router settings to a less crowded one.", "Смени канал Wi-Fi в настройках роутера на менее загруженный."),
    "log.router_silent": ("Router {gw} does not answer ping", "Роутер {gw} не отвечает на ping"),
    "find.router_down": ("Router does not answer", "Роутер не отвечает"),
    "tip.router_down": ("Check that the router is on, then power-cycle it for 10 seconds.", "Проверь, что роутер включён; перезагрузи его (выключи на 10 секунд)."),
    "find.router_ignore": ("Router does not answer ping", "Роутер не отвечает на ping"),
    "tip.router_ignore": ("The internet still works, so the router is probably ignoring ping.", "Интернет при этом есть — скорее всего, роутер просто игнорирует ping."),
    "log.router": ("Router {name}: {avg:.1f} ms, jitter {jitter:.1f}, loss {loss:.0f}%", "Роутер {name}: {avg:.1f} мс, джиттер {jitter:.1f}, потери {loss:.0f}%"),
    "find.router_unstable": ("Unstable link to the router ({loss:.0f}% loss, {avg:.0f} ms)", "Нестабильная связь с роутером (потери {loss:.0f}%, {avg:.0f} мс)"),
    "tip.router_unstable": ("The problem is between the Mac and the router: usually Wi-Fi noise, distance, or an overloaded router.", "Проблема между Mac и роутером: обычно это Wi-Fi — помехи, расстояние или перегруженный роутер."),
    "log.isp_down": ("Silence beyond the router: no internet server answers", "За роутером тишина: ни один сервер в интернете не отвечает"),
    "find.isp_down": ("No internet beyond the router", "Нет интернета за роутером"),
    "tip.isp_down": ("The router is up, but nothing gets out. Power-cycle it. If that does not help, call the ISP and check the account balance.", "Роутер жив, но наружу не выходит. Перезагрузи роутер; не помогло — звони провайдеру (проверь и баланс)."),
    "log.isp": ("ISP {org}: to 1.1.1.1 {latency}, loss {loss:.0f}%", "Провайдер {org}: до 1.1.1.1 {latency}, потери {loss:.0f}%"),
    "find.isp_unstable": ("The ISP link is unstable ({best:.0f} ms, up to {loss:.0f}% loss)", "Канал провайдера нестабилен ({best:.0f} мс, потери до {loss:.0f}%)"),
    "tip.isp_unstable": ("If the router still answers quickly, the problem is at the ISP. Power-cycle the router, and contact support if it keeps happening.", "Если роутер при этом отвечает быстро — проблема у провайдера. Перезагрузи роутер, а если повторяется — пиши в поддержку."),
    "find.captive": ("This network requires a sign-in", "Сеть требует авторизации"),
    "tip.captive": ("This is a captive portal (cafe, hotel, transit). Open any http site and sign in.", "Это сеть с входом через браузер (кафе, отель, метро). Открой любой сайт по http и войди."),
    "log.captive": ("Captive portal detected — sign-in required", "Обнаружен captive-портал — нужна авторизация"),
    "log.vpn_dead": ("{app} is on, but traffic does not pass through the tunnel", "{app} включён, но трафик через туннель не проходит"),
    "find.vpn_dead": ("VPN is not passing traffic", "VPN не пропускает трафик"),
    "tip.vpn_dead": ("{app} brought the tunnel up, but nothing gets through. Switch servers or restart the VPN.", "{app} поднял туннель, но дальше тишина. Переключи сервер или перезапусти VPN."),
    "log.vpn_ok": ("{app} → exit: {country} ({org}), latency {latency}", "{app} → выход: {country} ({org}), задержка {latency}"),
    "find.vpn_slow": ("Slow VPN server ({rtt:.0f} ms)", "Медленный VPN-сервер ({rtt:.0f} мс)"),
    "tip.vpn_slow": ("The server is far away or overloaded. Pick a closer one — Finland, the Netherlands, or Germany.", "Сервер далеко или перегружен. Выбери сервер поближе — Финляндия, Нидерланды, Германия."),
    "log.dns_down": ("System DNS ({dns}) does not answer", "Системный DNS ({dns}) не отвечает"),
    "find.dns_down": ("DNS is broken — sites will not open by name", "Не работает DNS — сайты не открываются по именам"),
    "tip.dns_down": ("Set DNS manually: System Settings → Network → Details → DNS → 1.1.1.1 and 77.88.8.8.{extra}", "Пропиши DNS вручную: Системные настройки → Сеть → Подробнее → DNS → 1.1.1.1 и 77.88.8.8.{extra}"),
    "tip.dns_extra": (" These answer directly: {names}.", " Напрямую отвечают: {names}."),
    "log.dns_fake": ("DNS answers with 198.18.x.x stand-ins — the VPN fake-ip mode, which is fine", "DNS отвечает подставными адресами 198.18.x.x — это режим fake-ip у VPN, всё нормально"),
    "log.dns": ("DNS {dns} answers in {avg:.0f} ms", "DNS {dns} отвечает за {avg:.0f} мс"),
    "find.dns_slow": ("DNS is slow ({avg:.0f} ms)", "DNS медленный ({avg:.0f} мс)"),
    "tip.dns_slow": ("Every new site opens late. Try DNS 1.1.1.1 or 77.88.8.8.", "Каждый новый сайт открывается с задержкой. Попробуй DNS 1.1.1.1 или 77.88.8.8."),
    "log.dns_filter": ("DNS {names} does not know youtube.com — the ISP is rewriting answers", "DNS {names} не знает youtube.com — провайдер подменяет ответы"),
    "tip.dns_filter": ("Queries to public DNS are intercepted, and blocked domains disappear. DNS-over-HTTPS or a VPN gets around it.", "Запросы к публичным DNS перехватываются и заблокированные домены «исчезают». Спасает DNS-over-HTTPS или VPN."),
    "tip.dns_filter_vpn": ("The ISP intercepts queries to public DNS. The VPN path is not affected.", "Запросы к публичным DNS перехватываются провайдером. Через VPN это не мешает."),
    "find.dns_filter": ("The ISP filters DNS ({names})", "Провайдер фильтрует DNS ({names})"),
    "tip.sites_vpn": ("It does not open through the VPN. Change the server in {app} or check the routing rules.", "Через VPN не открывается. Смени сервер в {app} или проверь правила маршрутизации."),
    "tip.sites_dpi": ("This looks like DPI blocking. A VPN or another bypass is needed.", "Похоже на блокировку через DPI — нужен VPN или обход блокировок."),
    "tip.sites_ip": ("The site address is unreachable — an IP block, or a problem on the site's side.", "Адрес сайта недоступен — блокировка по IP или проблема на стороне сайта."),
    "tip.sites_dns": ("DNS returns no address — a DNS block. DoH or a VPN can help.", "DNS не отдаёт адрес — блокировка через DNS. Помогут DoH или VPN."),
    "tip.sites_other": ("Try again later, or through a VPN.", "Попробуй ещё раз позже или через VPN."),
    "find.sites_bad": ("Will not open: {names} — {reason}", "Не открывается: {names} — {reason}"),
    "find.sites_slow": ("Slow to open: {names}", "Медленно открываются: {names}"),
    "tip.sites_slow": ("The sites are reachable, but they take more than 2.5 s — the link or VPN server is overloaded.", "Сайты доступны, но отвечают дольше 2.5 с — перегружен канал или VPN-сервер."),
    "find.sites_saved": ("VPN saves the day: {names}", "VPN выручает: {names}"),
    "tip.sites_saved": ("These sites are blocked directly and work through the tunnel.", "Напрямую эти сайты заблокированы, а через туннель работают."),
    "find.sites_direct": ("Works directly, but not through the VPN: {names}", "Напрямую работает, а через VPN нет: {names}"),
    "tip.sites_direct": ("Add these sites to the VPN direct-exclusion list.", "Добавь эти сайты в исключения VPN (direct), чтобы ходить к ним напрямую."),
    "headline.warn": ("Usable overall, with a few caveats", "В целом жить можно, но есть нюансы"),
    "headline.ok": ("The network is healthy. This crab is on vacation!", "Сеть здорова, как краб в отпуске!"),
    "reason.dpi": ("the connection breaks during TLS (DPI)", "соединение рвётся на TLS (DPI)"),
    "reason.ip": ("the server is unreachable by IP", "сервер недоступен по IP"),
    "reason.dns": ("a DNS problem", "проблема с DNS"),
    "reason.cert": ("the certificate was substituted", "подменён сертификат"),
    "reason.other": ("a connection error", "ошибка соединения"),
    "signal.excellent": ("excellent", "отличный"),
    "signal.good": ("good", "хороший"),
    "signal.weak": ("weak", "слабый"),
    "signal.very_weak": ("very weak", "очень слабый"),
    "band.5": ("5 GHz", "5 ГГц"),
    "band.6": ("6 GHz", "6 ГГц"),
    "band.24": ("2.4 GHz", "2.4 ГГц"),
    "unit.ms": ("ms", "мс"),
    "unit.s": ("s", "с"),
    "ui.role": ("network doctor", "сетевой доктор"),
    "ui.checked": ("{elapsed:.1f} {unit} · nodes checked: {done} of {total}", "{elapsed:.1f} {unit} · проверено узлов: {done} из {total}"),
    "ui.no_reply": ("no reply", "не отвечает"),
    "ui.loss": ("loss {loss:.0f}%", "потери {loss:.0f}%"),
    "ui.interface": ("Interface", "Интерфейс"),
    "ui.signal": ("Signal", "Сигнал"),
    "ui.network": ("Network", "Сеть"),
    "ui.channel": ("Channel", "Канал"),
    "ui.standard": ("Standard", "Стандарт"),
    "ui.mbps": ("Mbps", "Мбит/с"),
    "ui.to_router": ("To router", "До роутера"),
    "ui.isp": ("ISP", "Провайдер"),
    "ui.public_ip": ("Public IP", "Внешний IP"),
    "ui.via_vpn": ("Via VPN", "Через VPN"),
    "ui.yes": ("yes", "есть"),
    "ui.no": ("no", "нет"),
    "ui.sign_in": ("Sign-in", "Вход в сеть"),
    "ui.auth_required": ("authorization required!", "нужна авторизация!"),
    "ui.not_required": ("not required", "не нужен"),
    "ui.empty": ("empty", "пусто"),
    "ui.server": ("Server", "Сервер"),
    "ui.system_dns": ("  System DNS: ", "  Системный DNS: "),
    "ui.fake_ip": ("  — VPN fake-ip: the tunnel resolves names itself", "  — fake-ip от VPN: имена резолвит сам туннель"),
    "ui.average": ("  · {value} on average", "  · {value} в среднем"),
    "ui.site": ("Site", "Сайт"),
    "ui.via_vpn_col": ("via VPN", "через VPN"),
    "ui.direct": ("direct", "напрямую"),
    "ui.access": ("access", "доступ"),
    "ui.response": ("response", "ответ"),
    "ui.no_findings": ("No problems found. If something is still slow, it is probably the site or the app.", "Проблем не нашёл. Если что-то тормозит — дело, скорее всего, в самом сайте или приложении."),
    "ui.mood.happy": ("You can stay online in peace", "Можно спокойно сидеть в интернете"),
    "ui.mood.normal": ("A couple of small things — see below", "Есть пара мелочей — смотри ниже"),
    "ui.mood.worried": ("Something is off — the breakdown is below", "Кое-что не так — разбор ниже"),
    "ui.mood.sad": ("This is bad — but I can tell you what to do", "Дело плохо — но я подскажу, что делать"),
    "ui.health": ("network health", "здоровье сети"),
    "ui.unscored": ("not measurable", "не измерить"),
    "ui.local": ("LOCAL NETWORK", "ЛОКАЛЬНАЯ СЕТЬ"),
    "ui.internet": ("INTERNET", "ИНТЕРНЕТ"),
    "ui.sites": ("SITES", "САЙТЫ"),
    "ui.diagnosis": ("DIAGNOSIS", "ДИАГНОЗ"),
    "ui.checked_in": (" checked in {elapsed:.1f} {unit} ", " проверено за {elapsed:.1f} {unit} "),
    "cli.description": ("Eugene the crab finds out why the internet is down", "Краб Юджин выясняет, почему не работает интернет"),
    "cli.quick": ("faster check, fewer pings", "быстрая проверка (меньше пингов)"),
    "cli.site": ("check an extra site (repeatable)", "проверить ещё сайт (можно несколько раз)"),
    "cli.domain": ("DOMAIN", "ДОМЕН"),
    "cli.json": ("print the result as JSON", "вывести результат в JSON"),
    "cli.lang": ("language: ru or en; by default, Russian if it is the system language", "язык: ru или en; по умолчанию русский, если это язык системы"),
    "cli.interrupted": ("Eugene scuttled off. Interrupted.", "Юджин уполз. Прервано."),
    "cli.failed": ("Eugene could not finish the check:", "Юджин не смог закончить проверку:"),
    "error.dns_nx": ("domain does not resolve", "домен не резолвится"),
    "error.spoofed": ("DNS returned a spoofed address {ip}", "DNS вернул подменный адрес {ip}"),
    "error.dns_bad": ("malformed DNS reply", "битый ответ DNS"),
    "error.timeout": ("timeout", "таймаут"),
    "error.tcp_timeout": ("TCP timeout", "таймаут TCP"),
    "error.tls_timeout": ("TLS timeout", "таймаут TLS"),
    "error.no_response": ("no response", "нет ответа"),
    "error.cert": ("untrusted certificate", "чужой сертификат"),
    "error.tcp_reset": ("TCP reset", "сброс TCP"),
    "error.tls_drop": ("TLS dropped", "обрыв TLS"),
    "error.http_drop": ("response dropped", "обрыв ответа"),
    "error.refused": ("connection refused", "соединение отклонено"),
    "error.empty": ("empty response", "пустой ответ"),
}

_ERRORS = {
    "domain does not resolve": "error.dns_nx",
    "malformed DNS reply": "error.dns_bad",
    "timeout": "error.timeout",
    "TCP timeout": "error.tcp_timeout",
    "TLS timeout": "error.tls_timeout",
    "no response": "error.no_response",
    "untrusted certificate": "error.cert",
    "TCP reset": "error.tcp_reset",
    "TLS dropped": "error.tls_drop",
    "response dropped": "error.http_drop",
    "connection refused": "error.refused",
    "empty response": "error.empty",
}
_SPOOFED = "DNS returned a spoofed address "

_COUNTRIES = {
    "RU": ("Russia", "Россия"), "DE": ("Germany", "Германия"), "NL": ("Netherlands", "Нидерланды"),
    "FI": ("Finland", "Финляндия"), "SE": ("Sweden", "Швеция"), "IS": ("Iceland", "Исландия"),
    "US": ("United States", "США"), "GB": ("United Kingdom", "Великобритания"), "FR": ("France", "Франция"),
    "PL": ("Poland", "Польша"), "LV": ("Latvia", "Латвия"), "EE": ("Estonia", "Эстония"),
    "LT": ("Lithuania", "Литва"), "KZ": ("Kazakhstan", "Казахстан"), "TR": ("Turkey", "Турция"),
    "AE": ("UAE", "ОАЭ"), "JP": ("Japan", "Япония"), "SG": ("Singapore", "Сингапур"),
    "CH": ("Switzerland", "Швейцария"), "AT": ("Austria", "Австрия"), "CZ": ("Czechia", "Чехия"),
    "GE": ("Georgia", "Грузия"), "AM": ("Armenia", "Армения"), "RS": ("Serbia", "Сербия"),
    "HK": ("Hong Kong", "Гонконг"), "CA": ("Canada", "Канада"), "ES": ("Spain", "Испания"),
    "IT": ("Italy", "Италия"), "NO": ("Norway", "Норвегия"), "MD": ("Moldova", "Молдова"),
}


def use(lang):
    """Select ru or en for every later call to t()."""
    global language
    if lang not in ("ru", "en"):
        raise ValueError(lang)
    language = lang


def t(key, **kwargs):
    en, ru = _STRINGS[key]
    text = ru if language == "ru" else en
    return text.format(**kwargs) if kwargs else text


def fmt_ms(value):
    if value is None:
        return "—"
    number = "%.1f" % value if value < 10 else "%.0f" % value
    return number + " " + t("unit.ms")


def tr_error(message):
    """Translate a stable probe error. Unknown system errors pass through."""
    if not message:
        return message
    if message.startswith(_SPOOFED):
        return t("error.spoofed", ip=message[len(_SPOOFED):])
    key = _ERRORS.get(message)
    return t(key) if key else message


def country_name(code):
    pair = _COUNTRIES.get(code or "")
    if not pair:
        return code or "?"
    return pair[1] if language == "ru" else pair[0]


def detect_language():
    """Russian when it is the first system language, otherwise English."""
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["defaults", "read", "-g", "AppleLanguages"],
                capture_output=True, text=True, timeout=2,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        match = re.search(r'"([A-Za-z-]+)"', out)
        if match:
            return "ru" if match.group(1).lower().startswith("ru") else "en"
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(name, "")
        if value and value.lower() != "c":
            return "ru" if value.lower().startswith("ru") else "en"
    return "en"
