#!/usr/bin/env python3
"""apk-domains: for every app in a CSV -> download APK -> unzip + decompile -> extract domains ->
save ONLY the related domains to output/<AppName>.txt.

  python main.py batch applications.csv
  python main.py apk some.apk --name Bing
"""
import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:  # androguard spams DEBUG logs
    from loguru import logger
    logger.remove()
except Exception:
    pass

import decompile
import llm
import pipeline


def common(p):
    p.add_argument("--out", default="output")
    p.add_argument("--downloads", default="downloads")
    p.add_argument("--workers", type=int, default=4, help="apps processed in parallel (default 4)")
    p.add_argument("--resume", action="store_true", help="skip apps whose .txt already exists")
    p.add_argument("--no-decompile", action="store_true", help="fastest: zip scan only")
    p.add_argument("--no-apktool", action="store_true")
    p.add_argument("--jadx", action="store_true", help="also decompile to Java with jadx (slow, finds more)")
    p.add_argument("--llm", action="store_true", help="use local Llama on leftover unknown domains (slow)")
    p.add_argument("--model", default="llama3.1:8b")
    p.add_argument("--ollama", default="http://localhost:11434")
    p.add_argument("--max-llm", type=int, default=150, help="max domains sent to Llama per app")
    p.add_argument("--expand", action="store_true", help="add subdomains from crt.sh (internet)")
    p.add_argument("--dynamic", action="store_true", help="runtime capture on adb device + PCAPdroid")
    p.add_argument("--pcapdroid-key", default="")
    p.add_argument("--run-seconds", type=int, default=90)
    p.add_argument("--events", type=int, default=400)
    p.add_argument("--pcap", help="import an existing pcap/pcapng")
    p.add_argument("--full-report", action="store_true", help="also save all domains + categories as CSV")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("batch", help="CSV with columns: name,package,platform")
    b.add_argument("csv")
    b.add_argument("--limit", type=int, default=0)
    common(b)
    s = sub.add_parser("apk", help="analyze one local APK/XAPK/IPA")
    s.add_argument("file")
    s.add_argument("--name")
    s.add_argument("--package")
    s.add_argument("--platform", default="android")
    common(s)
    o = ap.parse_args()

    if o.llm:
        try:
            llm.check(o.ollama, o.model)
        except llm.OllamaError as e:
            sys.exit(f"[x] {e}")
    if o.dynamic:
        o.workers = 1
    out_root = Path(o.out)
    print("[*] Tools:", decompile.tools(), "| LLM:", "on" if o.llm else "off", "| jadx:", "on" if o.jadx else "off")

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

    def work(a):
        a = {k.strip().lower(): (v or "").strip() for k, v in a.items()}
        name = a.get("name") or a.get("app_name") or a.get("application") or ""
        return name, a.get("package") or a.get("bundle_id") or "", (a.get("platform") or "android").lower()

    failed, done = [], 0
    with ThreadPoolExecutor(max_workers=max(1, o.workers)) as ex:
        futs = {}
        for a in apps:
            name, pkg, plat = work(a)
            futs[ex.submit(pipeline.process_app, name, pkg, plat, o, out_root)] = (name, pkg)
        for fut in as_completed(futs):
            name, pkg = futs[fut]
            try:
                fut.result()
                done += 1
            except Exception as e:
                print(f"[x] {name or pkg}: FAILED - {e}")
                failed.append({"name": name, "package": pkg, "error": str(e)[:300]})

    out_root.mkdir(parents=True, exist_ok=True)
    if failed:
        with open(out_root / "failed.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["name", "package", "error"])
            w.writeheader()
            w.writerows(failed)
    print(f"\n[+] Finished: {done} ok, {len(failed)} failed. Text files are in {out_root}/ (failures: failed.csv)")


if __name__ == "__main__":
    main()
