"""Optional network expansion: crt.sh subdomains + DNS verification."""
from progress import log
import json
import socket
import urllib.request


def resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def crtsh(domain: str, limit=200) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "apk-domains"}), timeout=40) as r:
            rows = json.loads(r.read())
    except Exception as e:
        log(f"[!] crt.sh failed for {domain}: {e}")
        return set()
    names = set()
    for row in rows:
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and " " not in n:
                names.add(n)
            if len(names) >= limit:
                return names
    return names
