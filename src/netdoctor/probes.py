"""Низкоуровневые сетевые проверки: маршруты, Wi-Fi, ping, DNS, HTTPS.

Ключевая хитрость: на macOS сокет можно привязать к физическому интерфейсу
(IP_BOUND_IF), и тогда трафик идёт мимо VPN-туннеля. Так мы сравниваем
«через VPN» и «напрямую».
"""

import ipaddress
import json
import random
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time

IS_MAC = sys.platform == "darwin"
IP_BOUND_IF = 25  # macOS <netinet/in.h>
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) netdoctor"
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")  # fake-ip DNS у Clash / sing-box / Shadowrocket
TUNNEL_PREFIXES = ("utun", "tun", "ppp", "ipsec", "wg", "tap", "gpd")

VPN_APPS = {
    "shadowrocket": "Shadowrocket",
    "amneziavpn": "AmneziaVPN",
    "amneziawg": "AmneziaWG",
    "hiddify": "Hiddify",
    "v2raytun": "v2RayTun",
    "v2rayn": "v2rayN",
    "foxray": "FoXray",
    "streisand": "Streisand",
    "happ": "Happ",
    "karing": "Karing",
    "nekoray": "NekoRay",
    "clash": "Clash",
    "mihomo": "mihomo",
    "sing-box": "sing-box",
    "xray": "Xray",
    "outline": "Outline",
    "wireguard": "WireGuard",
    "openvpn": "OpenVPN",
    "tunnelblick": "Tunnelblick",
    "surge": "Surge",
    "stash": "Stash",
    "nordvpn": "NordVPN",
    "expressvpn": "ExpressVPN",
    "protonvpn": "Proton VPN",
    "mullvad": "Mullvad",
    "windscribe": "Windscribe",
    "psiphon": "Psiphon",
    "cloudflare warp": "Cloudflare WARP",
    "tailscale": "Tailscale",
}


# ────────────────────────────── система ───────────────────────────────


def sh(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def is_tunnel(iface):
    return bool(iface) and iface.startswith(TUNNEL_PREFIXES)


def default_routes():
    """[(gateway, iface)] всех маршрутов по умолчанию, в порядке приоритета."""
    routes = []
    if IS_MAC:
        for line in sh(["netstat", "-rn", "-f", "inet"]).splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "default":
                routes.append((parts[1], parts[3]))
        # split-туннель 0/1 + 128.0/1 тоже считается «VPN по умолчанию»
        for line in sh(["netstat", "-rn", "-f", "inet"]).splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("0/1", "128.0/1") and is_tunnel(parts[3]):
                routes.insert(0, (parts[1], parts[3]))
                break
    else:
        for line in sh(["ip", "route", "show", "default"]).splitlines():
            m = re.search(r"default via (\S+) dev (\S+)", line) or re.search(r"default dev (\S+)", line)
            if m and m.lastindex == 2:
                routes.append((m.group(1), m.group(2)))
            elif m:
                routes.append(("", m.group(1)))
    seen, uniq = set(), []
    for r in routes:
        if r[1] not in seen:
            seen.add(r[1])
            uniq.append(r)
    return uniq


def hardware_ports():
    ports = {}
    if IS_MAC:
        name = None
        for line in sh(["networksetup", "-listallhardwareports"]).splitlines():
            if line.startswith("Hardware Port:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and name:
                ports[line.split(":", 1)[1].strip()] = name
    return ports


def iface_ip(iface):
    if IS_MAC:
        return sh(["ipconfig", "getifaddr", iface]).strip() or None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", sh(["ip", "-4", "addr", "show", iface]))
    return m.group(1) if m else None


def system_dns():
    if IS_MAC:
        m = re.search(r"nameserver\[0\] : (\S+)", sh(["scutil", "--dns"]))
        return m.group(1) if m else None
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                return line.split()[1]
    except OSError:
        pass
    return None


def running_vpn_apps():
    procs = sh(["ps", "-axo", "comm"]).lower()
    found = []
    for key, name in VPN_APPS.items():
        if key in procs and name not in found:
            found.append(name)
    # приложение с активным Packet Tunnel — почти наверняка то, что держит туннель
    tunnel = re.findall(r"/applications/([^/]+)\.app/.*packettunnel", procs)
    active = [VPN_APPS.get(t, t.title()) for t in tunnel]
    return active + [a for a in found if a not in active]


def wifi_info():
    """Параметры текущей Wi-Fi сети (macOS). SSID без прав геолокации скрыт системой."""
    if not IS_MAC:
        return None
    try:
        data = json.loads(sh(["system_profiler", "SPAirPortDataType", "-json"], timeout=15) or "{}")
        for item in data.get("SPAirPortDataType", []):
            for itf in item.get("spairport_airport_interfaces", []):
                cur = itf.get("spairport_current_network_information")
                if not cur or "spairport_signal_noise" not in cur:
                    continue
                sig = re.findall(r"(-?\d+) dBm", cur.get("spairport_signal_noise", ""))
                ssid = cur.get("_name")
                return {
                    "iface": itf.get("_name"),
                    "ssid": None if not ssid or "redacted" in ssid else ssid,
                    "signal": int(sig[0]) if sig else None,
                    "noise": int(sig[1]) if len(sig) > 1 else None,
                    "channel": cur.get("spairport_network_channel"),
                    "phy": cur.get("spairport_network_phymode"),
                    "rate": cur.get("spairport_network_rate"),
                    "security": (cur.get("spairport_security_mode") or "").replace("spairport_security_mode_", ""),
                }
    except Exception:
        pass
    return None


# ──────────────────────────────── ping ────────────────────────────────


def ping(host, count=10, interval=0.2, iface=None, wait=2):
    cmd = ["ping", "-n", "-c", str(count), "-i", str(interval)]
    if iface:
        cmd += ["-b", iface] if IS_MAC else ["-I", iface]
    cmd += ["-t" if IS_MAC else "-w", str(int(count * interval + wait + 1))]
    out = sh(cmd + [host], timeout=count * interval + wait + 5)
    times = [float(x) for x in re.findall(r"time[=<]([\d.]+) ?ms", out)]
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    sent = int(m.group(1)) if m else count
    recv = int(m.group(2)) if m else len(times)
    return {
        "host": host,
        "sent": sent,
        "recv": recv,
        "loss": 100.0 * (sent - recv) / sent if sent else 100.0,
        "times": times,
        "avg": statistics.mean(times) if times else None,
        "min": min(times) if times else None,
        "jitter": statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0.0,
    }


# ──────────────────────────────── DNS ─────────────────────────────────


def bind(sock, iface):
    if iface and IS_MAC:
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(iface))


def _skip_name(data, i):
    while True:
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def dns_query(server, name, iface=None, timeout=2.0):
    """Прямой DNS-запрос (A) к серверу, опционально мимо VPN. → {ms, rcode, ips, error}"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bind(s, iface)
        s.settimeout(timeout)
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
        q += struct.pack(">HH", 1, 1)
        t0 = time.perf_counter()
        s.sendto(q, (server, 53))
        while True:
            data = s.recv(4096)
            if struct.unpack(">H", data[:2])[0] == tid:
                break
        ms = (time.perf_counter() - t0) * 1000
        rcode = data[3] & 0x0F
        an = struct.unpack(">H", data[6:8])[0]
        i = _skip_name(data, 12) + 4
        ips = []
        for _ in range(an):
            i = _skip_name(data, i)
            typ, _cls, _ttl, ln = struct.unpack(">HHIH", data[i : i + 10])
            i += 10
            if typ == 1 and ln == 4:
                ips.append(socket.inet_ntoa(data[i : i + 4]))
            i += ln
        return {"ms": ms, "rcode": rcode, "ips": ips, "error": None}
    except socket.timeout:
        return {"ms": None, "rcode": None, "ips": [], "error": "таймаут"}
    except Exception as e:
        return {"ms": None, "rcode": None, "ips": [], "error": str(e)}
    finally:
        s.close()


def resolve_system(name):
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        return {"ms": (time.perf_counter() - t0) * 1000, "ips": [i[4][0] for i in infos], "error": None}
    except Exception as e:
        return {"ms": None, "ips": [], "error": str(e)}


def ip_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "bad"
    if a in FAKE_IP_NET:
        return "fake"
    if a.is_unspecified or a.is_loopback or a.is_private or a.is_link_local:
        return "bogus"
    return "ok"


# ─────────────────────────────── HTTPS ────────────────────────────────


def http_probe(host, ip=None, iface=None, timeout=6.0, path="/", body_limit=0):
    """Поэтапный HTTPS-запрос: DNS → TCP → TLS → первый байт ответа.

    Возвращает тайминги каждого этапа (мс), HTTP-статус и, при ошибке,
    этап, на котором всё сломалось, — по нему видно, DNS это, блок IP или DPI.
    """
    r = {"host": host, "ip": ip, "dns": None, "tcp": None, "tls": None, "http": None,
         "status": None, "stage": None, "error": None, "body": b""}
    if ip is None:
        res = resolve_system(host)
        if not res["ips"]:
            r.update(stage="dns", error="домен не резолвится")
            return r
        r["dns"], ip = res["ms"], res["ips"][0]
        r["ip"] = ip
    if ip_kind(ip) == "bogus":
        r.update(stage="dns", error="DNS вернул подменный адрес %s" % ip)
        return r

    stage = "tcp"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind(s, iface)
        s.settimeout(timeout)
        t = time.perf_counter()
        s.connect((ip, 443))
        r["tcp"] = (time.perf_counter() - t) * 1000

        stage = "tls"
        t = time.perf_counter()
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
        r["tls"] = (time.perf_counter() - t) * 1000

        stage = "http"
        t = time.perf_counter()
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
               "Referer: https://%s/\r\nConnection: close\r\n\r\n") % (path, host, UA, host)
        s.sendall(req.encode())
        first = s.recv(4096)
        r["http"] = (time.perf_counter() - t) * 1000
        if not first:
            raise ConnectionResetError("пустой ответ")
        m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", first)
        r["status"] = int(m.group(1)) if m else None
        if body_limit:
            buf = first
            while len(buf) < body_limit:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            r["body"] = buf
    except socket.timeout:
        r.update(stage=stage, error={"tcp": "таймаут TCP", "tls": "таймаут TLS", "http": "нет ответа"}[stage])
    except ssl.SSLCertVerificationError:
        r.update(stage=stage, error="чужой сертификат")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLEOFError, ssl.SSLZeroReturnError):
        r.update(stage=stage, error={"tcp": "сброс TCP", "tls": "обрыв TLS", "http": "обрыв ответа"}[stage])
    except ConnectionRefusedError:
        r.update(stage=stage, error="соединение отклонено")
    except OSError as e:
        r.update(stage=stage, error=(e.strerror or str(e))[:40])
    finally:
        s.close()
    return r


def total_ms(r):
    return sum(r[k] for k in ("dns", "tcp", "tls", "http") if r.get(k))


def http_json(host, path, iface=None, ip=None, timeout=6.0):
    r = http_probe(host, ip=ip, iface=iface, timeout=timeout, path=path, body_limit=200_000)
    if r["error"] or not r["body"]:
        return None
    body = r["body"].split(b"\r\n\r\n", 1)[-1]
    if b"transfer-encoding: chunked" in r["body"].lower().split(b"\r\n\r\n", 1)[0]:
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            try:
                n = int(size_line.strip() or b"0", 16)
            except ValueError:
                break
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2 :]
        body = out
    try:
        return json.loads(body)
    except Exception:
        return None


def cf_meta(iface=None, ip=None):
    return http_json("speed.cloudflare.com", "/meta", iface=iface, ip=ip)


def http_rtt(host="speed.cloudflare.com", n=6):
    """Честная задержка до Cloudflare по HTTP поверх уже открытого соединения
    (работает и через VPN-туннель, где ICMP-ping врёт)."""
    import http.client

    try:
        conn = http.client.HTTPSConnection(host, timeout=6)
        times = []
        for i in range(n + 1):
            t = time.perf_counter()
            conn.request("GET", "/__down?bytes=0", headers={"User-Agent": UA})
            resp = conn.getresponse()
            resp.read()
            rtt = (time.perf_counter() - t) * 1000
            m = re.search(r"dur=([\d.]+)", resp.getheader("Server-Timing") or "")
            if m:
                rtt -= float(m.group(1))
            if i:  # первый — прогрев
                times.append(max(rtt, 0.1))
        conn.close()
        return statistics.median(times)
    except Exception:
        return None


def captive_portal(iface=None):
    """True — если сеть перехватывает HTTP (страница авторизации в кафе/отеле)."""
    s = socket.socket()
    try:
        bind(s, iface)
        s.settimeout(4)
        ip = socket.gethostbyname("captive.apple.com")
        if ip_kind(ip) == "fake":
            d = dns_query("77.88.8.8", "captive.apple.com", iface)
            ip = d["ips"][0] if d["ips"] else ip
        s.connect((ip, 80))
        s.sendall(b"GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\nConnection: close\r\n\r\n")
        data = b""
        try:
            while len(data) < 20000 and b"</HTML>" not in data.upper():
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        if not data:
            return None
        return b"Success" not in data
    except Exception:
        return None
    finally:
        s.close()


def network_blocked(gw, iface=None):
    """Проверяет, разрешено ли этой программе вообще открывать сетевые соединения.

    В песочницах и под фаерволами (Little Snitch, LuLu, MDM-профили) сокет
    отклоняется сразу, ещё до отправки пакета: EBADF / EPERM / EACCES.
    Отказ или таймаут от самого роутера — это нормально: значит, сеть доступна.
    Возвращает текст ошибки, если доступа нет, иначе None.
    """
    import errno

    denied = (errno.EBADF, errno.EPERM, errno.EACCES)
    for target, kind in (((gw, 80), socket.SOCK_STREAM), (("1.1.1.1", 53), socket.SOCK_DGRAM)):
        s = socket.socket(socket.AF_INET, kind)
        try:
            bind(s, iface)
            s.settimeout(1.0)
            s.connect(target)
            if kind == socket.SOCK_DGRAM:
                s.send(b"\0")
            return None
        except OSError as e:
            if e.errno not in denied:
                return None
            last = e.strerror or str(e)
        finally:
            s.close()
    return last


def ipv6_available():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        s.settimeout(2.5)
        s.connect(("2606:4700:4700::1111", 443))
        return True
    except Exception:
        return False
    finally:
        s.close()


ROUTER_BRANDS = ["keenetic", "mikrotik", "tp-link", "asus", "zyxel", "xiaomi", "huawei", "netgear",
                 "d-link", "tenda", "openwrt", "ubiquiti", "unifi", "eero", "sagemcom", "zte", "linksys", "fritz"]


def router_brand(gw, iface=None):
    s = socket.socket()
    try:
        bind(s, iface)
        s.settimeout(1.5)
        s.connect((gw, 80))
        s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % gw).encode())
        data = b""
        while len(data) < 30000:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        low = data.lower().decode("latin-1")
        if "ndm-" in low or "keeneticos" in low:
            return "Keenetic"
        for b in ROUTER_BRANDS:
            if b in low:
                return {"tp-link": "TP-Link", "d-link": "D-Link", "openwrt": "OpenWrt", "zte": "ZTE",
                        "mikrotik": "MikroTik", "asus": "ASUS", "zyxel": "Zyxel", "fritz": "FRITZ!Box"}.get(b, b.title())
    except Exception:
        pass
    finally:
        s.close()
    return None
