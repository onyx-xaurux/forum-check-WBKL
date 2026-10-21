import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlparse

import requests

CACHE_FILE = os.getenv("CACHE_FILE", "cache/dead_keys.json")
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
SB_BIN = os.getenv("SB_BIN", "sing-box")
TEST_URL = os.getenv("TEST_URL", "http://cp.cloudflare.com/generate_204")
WORKERS = int(os.getenv("WORKERS", "20"))
TIMEOUT = int(os.getenv("TIMEOUT", "8"))
DEAD_TTL_DAYS = float(os.getenv("DEAD_TTL_DAYS", "7"))  # 0 = мёртвые не перепроверяются никогда
BASE_PORT = 20000

XRAY_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
SB_SCHEMES = ("hysteria2://", "hy2://", "hysteria://", "anytls://")
SCHEMES = XRAY_SCHEMES + SB_SCHEMES
# эти форматы не проверяем, а сообщения с ними не удаляем
UNSUPPORTED_SCHEMES = ("tuic://", "wireguard://", "wg://", "shadowtls://",
                       "socks5://", "socks4://", "socks://")


class Unsupported(ValueError):
    """Формат не поддерживается: такой ключ не считаем мёртвым."""


def b64d(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


# ====================== Xray ======================
def build_stream(net: str, sec: str, q: dict) -> dict:
    net = {"h2": "http", "splithttp": "xhttp", "mkcp": "kcp", "raw": "tcp"}.get(net, net) or "tcp"
    if net not in ("tcp", "ws", "grpc", "httpupgrade", "xhttp", "http", "kcp"):
        raise Unsupported(f"транспорт {net}")
    path = unquote(q.get("path", "/")) or "/"
    host = q.get("host", "")
    s = {"network": net}

    if net == "ws":
        s["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": unquote(q.get("serviceName", "")),
                             "multiMode": q.get("mode") == "multi"}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        x = {"path": path, "host": host, "mode": q.get("mode", "auto")}
        if q.get("extra"):
            try:
                x["extra"] = json.loads(unquote(q["extra"]))
            except ValueError:
                pass
        s["xhttpSettings"] = x
    elif net == "http":
        s["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif net == "kcp":
        kcp = {"header": {"type": q.get("headerType") or "none"}}
        if q.get("seed"):
            kcp["seed"] = unquote(q["seed"])
        s["kcpSettings"] = kcp
    elif net == "tcp" and q.get("headerType") == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [host] if host else []}}}}

    sni = q.get("sni") or q.get("peer") or host
    if sec == "tls":
        s["security"] = "tls"
        tls = {"serverName": sni,
               "allowInsecure": q.get("allowInsecure", q.get("insecure", "0")) in ("1", "true")}
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        if q.get("alpn"):
            tls["alpn"] = unquote(q["alpn"]).split(",")
        s["tlsSettings"] = tls
    elif sec == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {
            "serverName": sni,
            "fingerprint": q.get("fp") or "chrome",
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": unquote(q.get("spx", "")),
        }
    return s


def build_outbound(key: str) -> dict:
    if key.startswith("vmess://"):
        d = json.loads(b64d(key[8:].split("#")[0]))
        net = d.get("net", "tcp")
        q = {"path": d.get("path", "/"), "host": d.get("host", ""), "sni": d.get("sni", ""),
             "fp": d.get("fp", ""), "alpn": d.get("alpn", ""), "headerType": d.get("type", ""),
             "serviceName": d.get("path", ""), "seed": d.get("path", "") if net == "kcp" else ""}
        sec = "tls" if d.get("tls") == "tls" else "none"
        return {"protocol": "vmess",
                "settings": {"vnext": [{"address": d["add"], "port": int(d["port"]), "users": [{
                    "id": d["id"], "alterId": int(d.get("aid", 0) or 0),
                    "security": d.get("scy", "auto")}]}]},
                "streamSettings": build_stream(net, sec, q)}

    if key.startswith("ss://"):
        body = key[5:].split("#")[0]
        if "?" in body:
            raise Unsupported("ss plugin")
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            dec = b64d(userinfo) if ":" not in unquote(userinfo) else unquote(userinfo)
            if ":" not in dec:
                dec = unquote(userinfo)
        else:
            dec = b64d(body)
            dec, hostport = dec.rsplit("@", 1)
        method, password = dec.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {"protocol": "shadowsocks",
                "settings": {"servers": [{"address": host.strip("[]"), "port": int(port),
                                          "method": method, "password": password}]}}

    u = urlparse(key)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    user = unquote(u.username or "")

    if key.startswith("vless://"):
        stream = build_stream(q.get("type", "tcp"), q.get("security", "none"), q)
        return {"protocol": "vless",
                "settings": {"vnext": [{"address": u.hostname, "port": u.port, "users": [{
                    "id": user, "encryption": q.get("encryption", "none"),
                    "flow": q.get("flow", "")}]}]},
                "streamSettings": stream}

    if key.startswith("trojan://"):
        # у trojan без параметра security по умолчанию подразумевается tls
        stream = build_stream(q.get("type", "tcp"), q.get("security", "tls"), q)
        return {"protocol": "trojan",
                "settings": {"servers": [{"address": u.hostname, "port": u.port, "password": user}]},
                "streamSettings": stream}

    raise Unsupported("схема")


def build_xray_config(key: str, port: int) -> dict:
    out = build_outbound(key)
    out["tag"] = "proxy"
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [out],
    }


# ====================== sing-box ======================
def split_uri(key: str):
    body = key.split("://", 1)[1].split("#")[0]
    main, _, query = body.partition("?")
    userinfo, _, hostport = main.rstrip("/").rpartition("@")
    q = {k: v[0] for k, v in parse_qs(query).items()}
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        port_s = rest.lstrip(":")
    else:
        host, _, port_s = hostport.partition(":")
    if not host:
        raise ValueError("нет host")
    return unquote(userinfo), host, port_s, q


def parse_ports(port_s: str, q: dict):
    tokens = [t for t in port_s.split(",") if t]
    if q.get("mport"):
        tokens += q["mport"].split(",")
    single, ranges = None, []
    for t in tokens:
        if "-" in t:
            a, b = t.split("-", 1)
            ranges.append(f"{a}:{b}")
        elif single is None:
            single = int(t)
    if single is None:
        single = int(ranges[0].split(":")[0]) if ranges else 443
    return single, ranges


def sb_tls(q: dict, host: str, alpn_default=None) -> dict:
    insecure = (any(q.get(k) in ("1", "true") for k in ("insecure", "allowInsecure", "allow_insecure"))
                or bool(q.get("pinSHA256")))  # pin обычно означает самоподписанный сертификат
    tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or host,
           "insecure": insecure}
    if q.get("alpn"):
        tls["alpn"] = unquote(q["alpn"]).split(",")
    elif alpn_default:
        tls["alpn"] = alpn_default
    return tls


def build_singbox_config(key: str, port: int) -> dict:
    scheme = key.split("://", 1)[0]
    userinfo, host, port_s, q = split_uri(key)
    sport, ranges = parse_ports(port_s, q)

    if scheme in ("hysteria2", "hy2"):
        ob = {"type": "hysteria2", "server": host, "server_port": sport,
              "password": userinfo, "tls": sb_tls(q, host, ["h3"])}
        if ranges:
            ob["server_ports"] = ranges
        if q.get("obfs") == "salamander":
            ob["obfs"] = {"type": "salamander", "password": q.get("obfs-password", "")}
    elif scheme == "hysteria":
        if q.get("protocol", "udp") != "udp":
            raise Unsupported("hysteria faketcp/wechat")

        def mbps(name):
            return int(re.sub(r"\D", "", q.get(name, "")) or 100)

        ob = {"type": "hysteria", "server": host, "server_port": sport,
              "up_mbps": mbps("upmbps"), "down_mbps": mbps("downmbps"),
              "auth_str": q.get("auth", ""), "tls": sb_tls(q, host, ["h3"])}
        if q.get("obfsParam"):
            ob["obfs"] = q["obfsParam"]
    elif scheme == "anytls":
        ob = {"type": "anytls", "server": host, "server_port": sport,
              "password": userinfo, "tls": sb_tls(q, host)}
    else:
        raise Unsupported(scheme)

    ob["tag"] = "proxy"
    return {"log": {"disabled": True},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [ob]}


# ====================== проверка ======================
def wait_port(port: int, proc: subprocess.Popen, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def check_key(key: str, port: int):
    """True = рабочий, False = мёртвый, None = формат не поддерживается."""
    try:
        if key.startswith(SB_SCHEMES):
            text = json.dumps(build_singbox_config(key, port))
            cmd, startup = [SB_BIN, "run", "-c"], 8.0
        else:
            text = json.dumps(build_xray_config(key, port))
            cmd, startup = [XRAY_BIN, "run", "-c"], 4.0
    except Unsupported:
        return None
    except Exception:
        return False

    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write(text)

    proc = subprocess.Popen(cmd + [path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port, proc, startup):
            return False
        proxy = f"socks5h://127.0.0.1:{port}"
        for _ in range(2):  # 2 попытки, чтобы случайный таймаут не убил рабочий ключ
            try:
                r = requests.get(TEST_URL, proxies={"http": proxy, "https": proxy},
                                 timeout=TIMEOUT, allow_redirects=False)
                if r.status_code in (200, 204):
                    return True
            except requests.RequestException:
                pass
        return False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.remove(path)
        except OSError:
            pass


# ====================== кэш мёртвых ======================
def key_id(key: str) -> str:
    # без #названия: тег меняется, а сам ключ тот же
    return hashlib.sha1(key.split("#")[0].encode()).hexdigest()


def load_cache() -> dict:
    try:
        with open(CACHE_FILE) as f:
            cache = json.load(f)
    except (OSError, ValueError):
        return {}
    if DEAD_TTL_DAYS > 0:
        limit = time.time() - DEAD_TTL_DAYS * 86400
        cache = {k: t for k, t in cache.items() if t >= limit}
    return cache


def save_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_FILE) or ".", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)
