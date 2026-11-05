"""Hostname + API-endpoint extraction from APK/IPA zips and decompiled source trees."""
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import rules

URL_RE = re.compile(rb"(?:https?|wss?|ftp)://(?:[\w.~%!$&'()*+,;=:-]+@)?([A-Za-z0-9][A-Za-z0-9.-]{1,252})(?::\d{1,5})?"
                    rb"(/[A-Za-z0-9._~%!$&*+,;=:@/\-?]{0,200})?")
BARE_RE = re.compile(rb"(?<![A-Za-z0-9._/@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![A-Za-z0-9_-])")
# Retrofit-style endpoint annotations in decompiled Java/Kotlin
RETROFIT_RE = re.compile(rb'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*(?:value\s*=\s*)?"([^"]{1,200})"')
# HTTP client base URLs: baseUrl("..."), .url("..."), HttpUrl.parse("..."), BASE_URL = "..."
CLIENT_RE = re.compile(rb'(?:baseUrl|\.url|HttpUrl\.(?:parse|get)|BASE_URL\w*|API_URL\w*|API_BASE\w*|ENDPOINT\w*)'
                       rb'\s*(?:\(|=)\s*"((?:https?|wss?)://[A-Za-z0-9.-]+)')
CONST_RE = re.compile(rb'\w*(?:api|base|host|server|url|endpoint|domain)\w*\s*=\s*"((?:https?://)?[a-z0-9][a-z0-9.-]+\.[a-z]{2,})', re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

GTLDS = set("""com net org info biz io co app dev ai cloud online site tech xyz edu gov mil int mobi me tv
cc ly store shop live news media link page one pro name club top icu work world zone email network
systems services global digital agency solutions bank money pay games game video""".split())
EXT_BLOCK = set("""png jpg jpeg gif xml json so js java kt html htm css txt mp3 mp4 webp svg ttf otf dex apk pb
proto bin dat cfg properties arsc class jar zip gz py sh md yml yaml ini lock tflite bak log wav ogg
aar pem crt key cer pdf doc xls csv db sql map ts tsx jsx swift smali""".split())
PKG_ROOTS = {"java", "javax", "android", "androidx", "kotlin", "kotlinx", "dalvik", "sun", "libcore",
             "okhttp3", "okio", "retrofit2", "junit", "org", "net", "com", "io"}
CODE_EXT = {".java", ".kt", ".smali", ".xml", ".json", ".txt", ".properties", ".js", ".html", ".plist", ".yml", ".yaml"}


class Findings:
    def __init__(self):
        self.hosts = {}        # host -> {sources, count, via_url, paths, api}
        self.endpoints = set()  # Retrofit-style relative endpoints

    def add(self, host, kind, via_url=False, path=None, api=None):
        if not host:
            return
        e = self.hosts.setdefault(host, {"sources": set(), "count": 0, "via_url": False, "paths": set(), "api": set()})
        e["sources"].add(kind)
        e["count"] += 1
        e["via_url"] |= via_url
        if path and path != "/" and len(e["paths"]) < 15:
            e["paths"].add(path)
        if path and rules.API_PATH_RE.search(path):
            e["api"].add("path:" + path[:40])
        if api:
            e["api"].add(api)
        h = rules.host_api_hint(host)
        if h:
            e["api"].add(h)


def clean_host(h: bytes, from_url: bool):
    try:
        host = h.decode("ascii").lower().strip(".")
    except UnicodeDecodeError:
        return None
    if host.startswith(("http://", "https://")):
        host = host.split("://", 1)[1]
    if "." not in host or ".." in host or len(host) > 253 or IP_RE.match(host):
        return None
    labels = host.split(".")
    tld = labels[-1]
    if any(len(l) > 63 or l.startswith("-") or l.endswith("-") for l in labels) or not tld.isalpha():
        return None
    if tld in EXT_BLOCK:
        return None
    if not from_url:
        if labels[0] in PKG_ROOTS or not (tld in GTLDS or len(tld) == 2):
            return None
    elif len(tld) < 2:
        return None
    return host


def kind_of(name: str) -> str:
    n = name.lower()
    if n.endswith(".dex"):
        return "dex"
    if n.endswith("androidmanifest.xml"):
        return "manifest"
    if n.endswith(".arsc") or n.startswith("res/"):
        return "resources"
    if n.endswith(".so"):
        return "native"
    if n.endswith("info.plist") or "/frameworks/" in n:
        return "ios"
    return "assets"


def scan_bytes(data: bytes, kind: str, F: Findings, utf16: bool = False, code: bool = False):
    variants = [data] + ([data.replace(b"\x00", b"")] if utf16 else [])
    for blob in variants:
        for m in URL_RE.finditer(blob):
            host = clean_host(m.group(1), True)
            path = m.group(2).decode("ascii", "ignore") if m.group(2) else None
            F.add(host, kind, True, path)
        for m in BARE_RE.finditer(blob):
            F.add(clean_host(m.group(1), False), kind)
        if code:
            for m in CLIENT_RE.finditer(blob):
                F.add(clean_host(m.group(1), True), kind, True, api="http-client-baseurl")
            for m in CONST_RE.finditer(blob):
                F.add(clean_host(m.group(1), False if not m.group(1).startswith(b"http") else True), kind, api="const-name")
            for m in RETROFIT_RE.finditer(blob):
                F.endpoints.add(m.group(1).decode("ascii", "ignore"))


def scan_zip(path: Path, F: Findings):
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size > 150_000_000:
                continue
            kind = kind_of(info.filename)
            try:
                data = z.read(info)
            except Exception:
                continue
            scan_bytes(data, kind, F, utf16=kind in ("manifest", "resources"))


def scan_dir(root: Path, kind: str, F: Findings):
    """Scan a decompiled tree (jadx java/kotlin, apktool smali/xml)."""
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in CODE_EXT and p.stat().st_size < 20_000_000:
            try:
                scan_bytes(p.read_bytes(), kind, F, code=True)
            except Exception:
                pass


def get_package(apk: Path):
    """Return (package, app_label) using androguard or aapt if available."""
    for mod in ("androguard.core.apk", "androguard.core.bytecodes.apk"):
        try:
            APK = __import__(mod, fromlist=["APK"]).APK
            a = APK(str(apk))
            return a.get_package(), a.get_app_name()
        except Exception:
            continue
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        out = subprocess.run([aapt, "dump", "badging", str(apk)], capture_output=True, text=True).stdout
        pkg = re.search(r"package: name='([^']+)'", out)
        lab = re.search(r"application-label:'([^']+)'", out)
        return (pkg.group(1) if pkg else None, lab.group(1) if lab else None)
    return None, None
