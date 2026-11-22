#!/usr/bin/env python3
"""Build a single Happ full-Xray config with client-side least-ping selection.

Only Xray-compatible share links are included. Hysteria2/tuic and transports
that cannot be represented safely are deliberately skipped.
"""
import base64
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

def b64decode(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode()).decode("utf-8")

def first(qs, key, default=""):
    values = qs.get(key)
    return values[0] if values else default

def parse_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("bad port")
    return port

def stream_settings(network, security, qs, vmess=None):
    network = (network or "tcp").lower()
    if network not in {"tcp", "ws", "grpc", "xhttp"}:
        raise ValueError("unsupported transport")
    result = {"network": network, "security": "none"}
    if network == "ws":
        result["wsSettings"] = {
            "path": first(qs, "path", (vmess or {}).get("path", "/")),
            "headers": {"Host": first(qs, "host", (vmess or {}).get("host", ""))}
        }
        if not result["wsSettings"]["headers"]["Host"]:
            result["wsSettings"].pop("headers")
    elif network == "grpc":
        service = first(qs, "serviceName", first(qs, "service_name", (vmess or {}).get("path", "").strip("/")))
        result["grpcSettings"] = {"serviceName": service}
        authority = first(qs, "authority", (vmess or {}).get("host", ""))
        if authority:
            result["grpcSettings"]["authority"] = authority
    elif network == "xhttp":
        result["xhttpSettings"] = {
            "path": first(qs, "path", (vmess or {}).get("path", "/")),
            "mode": first(qs, "mode", "auto")
        }
        host = first(qs, "host", (vmess or {}).get("host", ""))
        if host:
            result["xhttpSettings"]["host"] = host

    if security == "reality":
        result["security"] = "reality"
        reality = {
            "serverName": first(qs, "sni", first(qs, "serverName", "")),
            "fingerprint": first(qs, "fp", "chrome"),
            "publicKey": first(qs, "pbk", ""),
            "shortId": first(qs, "sid", "")
        }
        spider = first(qs, "spx", "")
        if spider:
            reality["spiderX"] = spider
        if not reality["serverName"] or not reality["publicKey"]:
            raise ValueError("incomplete Reality parameters")
        result["realitySettings"] = reality
    elif security == "tls" or (vmess and str(vmess.get("tls", "")).lower() in {"tls", "true", "1"}):
        result["security"] = "tls"
        tls = {
            "serverName": first(qs, "sni", (vmess or {}).get("sni", "")),
            "fingerprint": first(qs, "fp", (vmess or {}).get("fp", "chrome")),
            "allowInsecure": first(qs, "allowInsecure", "false").lower() in {"1", "true"}
        }
        alpn = first(qs, "alpn", (vmess or {}).get("alpn", ""))
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]
        result["tlsSettings"] = tls
    return result

def convert(uri):
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    qs = parse_qs(parsed.query, keep_blank_values=True)
    name = unquote(parsed.fragment) or "HEX node"
    if scheme == "vless":
        host, port = parsed.hostname, parse_port(parsed.port)
        user_id = unquote(parsed.username or "")
        if not host or not user_id:
            raise ValueError("missing VLESS host/id")
        user = {"id": user_id, "encryption": "none"}
        flow = first(qs, "flow")
        if flow:
            user["flow"] = flow
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream_settings(first(qs, "type", "tcp"), first(qs, "security", "none"), qs)
        }
    elif scheme == "vmess":
        payload = uri.split("://", 1)[1].split("#", 1)[0]
        data = json.loads(b64decode(payload))
        host = data.get("add", "")
        port = parse_port(data.get("port"))
        user_id = data.get("id", "")
        if not host or not user_id:
            raise ValueError("missing VMess host/id")
        user = {"id": user_id, "alterId": int(data.get("aid", 0)), "security": data.get("scy", "auto")}
        net = data.get("net", "tcp")
        vmess_qs = {
            "sni": [data.get("sni", "")],
            "fp": [data.get("fp", "chrome")],
            "host": [data.get("host", "")],
            "path": [data.get("path", "/")],
            "alpn": [data.get("alpn", "")]
        }
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream_settings(net, "tls" if data.get("tls") else "none", vmess_qs, data)
        }
        name = data.get("ps") or name
    elif scheme == "trojan":
        host, port = parsed.hostname, parse_port(parsed.port)
        password = unquote(parsed.username or "")
        if not host or not password:
            raise ValueError("missing Trojan host/password")
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": stream_settings(first(qs, "type", "tcp"), first(qs, "security", "tls"), qs)
        }
    elif scheme == "ss":
        if "plugin" in qs:
            raise ValueError("Shadowsocks plugins are not supported in this builder")
        raw = uri.split("://", 1)[1].split("#", 1)[0]
        if "@" not in raw:
            decoded = b64decode(raw)
            userinfo, endpoint = decoded.rsplit("@", 1)
        else:
            userinfo, endpoint = raw.rsplit("@", 1)
            try:
                userinfo = b64decode(userinfo)
            except Exception:
                userinfo = unquote(userinfo)
        if ":" not in userinfo:
            raise ValueError("bad Shadowsocks credentials")
        method, password = userinfo.split(":", 1)
        supported_methods = {
            "aes-128-gcm", "aes-256-gcm",
            "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        }
        if method.lower() not in supported_methods:
            raise ValueError(f"unsupported Shadowsocks cipher: {method}")
        endpoint_parsed = urlsplit("ss://" + endpoint)
        host, port = endpoint_parsed.hostname, parse_port(endpoint_parsed.port)
        if not host:
            raise ValueError("missing Shadowsocks host")
        outbound = {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]}
        }
    else:
        raise ValueError("unsupported protocol")
    return name, outbound

def main(source, target):
    lines = Path(source).read_text(encoding="utf-8").splitlines()
    outbounds = []
    seen = set()
    skipped = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        try:
            name, outbound = convert(line)
            fingerprint = json.dumps(outbound, sort_keys=True)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            outbound["tag"] = f"hex-node-{len(outbounds)+1:03d}"
            outbounds.append(outbound)
        except Exception as exc:
            scheme = line.split("://", 1)[0].lower()
            skipped[scheme] = skipped.get(scheme, 0) + 1
            print(f"Skipping {scheme}: {exc}")
    if len(outbounds) < 3:
        raise SystemExit(f"Refusing to publish AutoSelect: only {len(outbounds)} Xray-compatible nodes.")
    tags = [x["tag"] for x in outbounds]
    config = {
        "remarks": "⚡ HEX | АВТОВЫБОР",
        "meta": {"serverDescription": "Автоматический выбор по задержке • HEX VPN"},
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {"allowTransparent": False}}
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "hex-auto"}],
            "balancers": [{
                "tag": "hex-auto", "selector": ["hex-node-"], "fallbackTag": tags[0],
                "strategy": {"type": "leastPing"}
            }]
        },
        "observatory": {
            "subjectSelector": ["hex-node-"],
            "probeUrl": "https://cp.cloudflare.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True
        },
        "stats": {}
    }
    Path(target).write_text(json.dumps([config], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Built one HEX AutoSelect profile with {len(outbounds)} Xray nodes; skipped: {skipped}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
