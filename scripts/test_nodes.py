#!/usr/bin/env python3
"""Test individual Xray outbounds through real HTTPS before publishing AutoSelect."""
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path

CONFIG = Path("autoselect.json")
TEST_CONFIG = Path("node-test-config.json")
MAP = Path("node-test-map.json")
SOURCE_MAP = Path("node-source-map.json")
SUBSCRIPTION = Path("subscription.txt")
BASE_PORT = 21000
MAX_NODES = 120
URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
)

def load_profile():
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) != 1:
        raise SystemExit("Expected exactly one HEX AutoSelect profile")
    return data[0]

def prepare():
    profile = load_profile()
    nodes = [x for x in profile.get("outbounds", []) if x.get("tag", "").startswith("hex-node-")]
    nodes = nodes[:MAX_NODES]
    if not nodes:
        raise SystemExit("No candidate nodes to test")
    inbounds, rules, mapping = [], [], []
    for i, node in enumerate(nodes):
        inbound_tag = f"hex-test-{i:03d}"
        port = BASE_PORT + i
        inbounds.append({
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        })
        rules.append({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": node["tag"]
        })
        mapping.append({"tag": node["tag"], "port": port})
    test_config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": nodes,
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    }
    TEST_CONFIG.write_text(json.dumps(test_config, ensure_ascii=False), encoding="utf-8")
    MAP.write_text(json.dumps(mapping), encoding="utf-8")
    print(f"Prepared real HTTPS checks for {len(mapping)} individual nodes.")

def check_one(item):
    tag, port = item["tag"], item["port"]
    for url in URLS:
        try:
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--fail",
                 "--socks5-hostname", f"127.0.0.1:{port}",
                 "--connect-timeout", "5", "--max-time", "14",
                 "--output", "/dev/null", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=17,
                check=False,
            )
            if result.returncode == 0:
                return tag, True, url
        except (subprocess.TimeoutExpired, OSError):
            pass
    return tag, False, ""

def finish():
    profile = load_profile()
    mapping = json.loads(MAP.read_text(encoding="utf-8"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(check_one, mapping))
    passed = {tag for tag, ok, _ in results if ok}
    tested = [
        x for x in profile.get("outbounds", [])
        if x.get("tag", "").startswith("hex-node-") and x.get("tag") in passed
    ]
    # Prefer encrypted TLS/REALITY transports; do not publish bare Shadowsocks
    # as the primary solution for restrictive mobile networks.
    nodes = [
        x for x in tested
        if x.get("protocol") in {"vless", "vmess", "trojan"}
        and x.get("streamSettings", {}).get("security") in {"tls", "reality"}
    ]
    priority = {"vless": 0, "trojan": 1, "vmess": 2}
    nodes.sort(key=lambda x: (priority.get(x.get("protocol"), 9), x.get("tag", "")))
    print(f"End-to-end HTTPS: {len(tested)}/{len(mapping)} nodes passed; {len(nodes)} TLS/REALITY nodes retained.")
    if not nodes:
        raise SystemExit("No TLS/REALITY node passed real HTTPS checks; refusing to publish.")
    tags = [x["tag"] for x in nodes]
    profile["outbounds"] = nodes + [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ]
    profile["routing"]["balancers"] = [{
        "tag": "hex-auto",
        "selector": ["hex-node-"],
        "fallbackTag": tags[0],
        "strategy": {"type": "leastPing"},
    }]
    profile["observatory"]["subjectSelector"] = ["hex-node-"]
    profile["meta"]["serverDescription"] = (
        f"HEX VPN • {len(nodes)} серверов прошли индивидуальный HTTPS-тест"
    )
    CONFIG.write_text(json.dumps([profile], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Keep the regular share-link subscription in sync with the exact same
    # individually HTTPS-tested TLS/REALITY nodes used by AutoSelect.
    source_map = json.loads(SOURCE_MAP.read_text(encoding="utf-8"))
    source_lines = {item["tag"]: item["line"] for item in source_map}
    selected_lines = [source_lines[tag] for tag in tags if tag in source_lines]
    if len(selected_lines) < 3:
        raise SystemExit(
            f"Only {len(selected_lines)} individually tested subscription nodes; refusing to publish."
        )
    current_lines = SUBSCRIPTION.read_text(encoding="utf-8").splitlines()
    headers = [line for line in current_lines if not line.strip() or line.lstrip().startswith("#")]
    SUBSCRIPTION.write_text("\n".join(headers + selected_lines) + "\n", encoding="utf-8")
    print(
        f"Published {len(nodes)} individually HTTPS-tested TLS/REALITY nodes "
        "to both AutoSelect and the regular HEX VPN subscription."
    )

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "finish"}:
        raise SystemExit("Usage: test_nodes.py prepare|finish")
    prepare() if sys.argv[1] == "prepare" else finish()
