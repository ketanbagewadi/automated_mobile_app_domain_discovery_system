#!/usr/bin/env python3
"""apk-domains: download an app, unpack + decompile it, and extract/classify every related domain
(static, API, CDN, runtime) with a local Llama 3 via Ollama.

  python main.py batch applications.csv
  python main.py apk some.apk --name Bing --package com.microsoft.bing
"""
import argparse
import csv
import sys
from pathlib import Path

import decompile
import llm
import pipeline


def common(p):
    p.add_argument("--model", default="llama3.1:8b", help="Ollama model (default llama3.1:8b)")
    p.add_argument("--ollama", default="http://localhost:11434")
    p.add_argument("--no-llm", action="store_true", help="rules only, skip Llama")
    p.add_argument("--no-decompile", action="store_true", help="zip scan only (skip apktool + jadx)")
    p.add_argument("--no-apktool", action="store_true")
    p.add_argument("--no-jadx", action="store_true")
    p.add_argument("--suggest", action="store_true", help="ask Llama for extra related domains (DNS-verified)")
    p.add_argument("--expand", action="store_true", help="subdomains via crt.sh for first-party domains")
    p.add_argument("--dynamic", action="store_true", help="run on adb device/emulator + PCAPdroid capture")
    p.add_argument("--pcapdroid-key", default="", help="PCAPdroid API key")
    p.add_argument("--run-seconds", type=int, default=90)
    p.add_argument("--events", type=int, default=400, help="monkey UI events")
    p.add_argument("--pcap", help="import an existing pcap/pcapng (Wireshark, PCAPdroid, tcpdump)")
    p.add_argument("--out", default="output")
    p.add_argument("--downloads", default="downloads")
    p.add_argument("--resume", action="store_true", help="skip apps already processed")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("batch", help="process every app in a CSV (columns: name,package,platform)")
    b.add_argument("csv")
    b.add_argument("--limit", type=int, default=0)
    common(b)
    s = sub.add_parser("apk", help="analyze a local APK/XAPK/IPA")
    s.add_argument("file")
    s.add_argument("--name")
    s.add_argument("--package")
    s.add_argument("--platform", default="android")
    common(s)
    o = ap.parse_args()

    if not o.no_llm:
        try:
            llm.check(o.ollama, o.model)
        except llm.OllamaError as e:
            sys.exit(f"[x] {e}")
    print("[*] Tools:", {**decompile.tools()})
    out_root = Path(o.out)

    if o.cmd == "apk":
        f = Path(o.file)
        if not f.exists():
            sys.exit(f"File not found: {f}")
        from extractor import get_package
        pkg = o.package or (get_package(f)[0] if f.suffix == ".apk" else None) or f.stem
        pipeline.process_app(o.name, pkg, o.platform, o, out_root, local_file=f)
        return

    apps = list(csv.DictReader(open(o.csv, newline="", encoding="utf-8-sig")))
    if o.limit:
        apps = apps[:o.limit]
    combined, failed = [], []
    for i, a in enumerate(apps, 1):
        a = {k.strip().lower(): (v or "").strip() for k, v in a.items()}
        name = a.get("name") or a.get("app_name") or a.get("application") or ""
        pkg = a.get("package") or a.get("bundle_id") or ""
        platform = (a.get("platform") or "android").lower()
        print(f"\n===== [{i}/{len(apps)}] {name or pkg} ({platform}) =====")
        try:
            rows = pipeline.process_app(name, pkg, platform, o, out_root)
            for r in rows or []:
                combined.append({"app": name or pkg, "package": pkg, **r})
        except Exception as e:
            print(f"[x] FAILED: {e}")
            failed.append({"name": name, "package": pkg, "error": str(e)[:300]})

    out_root.mkdir(parents=True, exist_ok=True)
    if combined:
        with open(out_root / "all_domains.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["app", "package"] + pipeline.FIELDS)
            w.writeheader()
            w.writerows(combined)
    if failed:
        with open(out_root / "failed.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["name", "package", "error"])
            w.writeheader()
            w.writerows(failed)
    print(f"\n[+] Done. {len(apps) - len(failed)} ok, {len(failed)} failed. Combined: {out_root / 'all_domains.csv'}")


if __name__ == "__main__":
    main()
