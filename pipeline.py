"""Per-app pipeline: download -> unpack -> scan (+decompile) -> keep related domains -> <AppName>.txt"""
import csv
import json
import re
from pathlib import Path

import decompile
import downloader
import dynamic
import expand
import extractor
import llm
import rules

RELATED = {"first_party", "same_company", "cdn_infra"}
FIELDS = ["domain", "registered_domain", "category", "related", "is_api", "api_evidence", "sample_paths",
          "confidence", "reason", "source"]


def safe_name(s: str) -> str:
    return re.sub(r"[^\w\-. ]+", "_", s).strip(" ._") or "app"


def analyze(apks, name, package, o):
    F = extractor.Findings()
    for apk in apks:
        extractor.scan_zip(apk, F)
        if not o.no_decompile:
            decompile.run(apk, F, use_apktool=not o.no_apktool, use_jadx=o.jadx)

    if getattr(o, "pcap", None):
        dynamic.parse_pcap(Path(o.pcap), F)
    if getattr(o, "dynamic", False):
        try:
            dynamic.capture(apks, package, F, o.pcapdroid_key, o.run_seconds, o.events)
        except Exception as e:
            print(f"[!] runtime capture failed: {e}")

    tokens = rules.brand_tokens(name, package)
    rows, undecided = {}, []
    for host, info in sorted(F.hosts.items()):
        if rules.is_noise(host):
            continue
        row = dict(domain=host, category="unknown", confidence=0.0, reason="",
                   is_api=bool(info["api"]), api_evidence=";".join(sorted(info["api"]))[:150],
                   sample_paths=" ".join(sorted(info["paths"])[:5]), source=",".join(sorted(info["sources"])))
        r = rules.rule_classify(host, tokens)
        if r:
            row.update(category=r[0], confidence=r[1], reason=r[2])
        else:
            undecided.append(host)
        rows[host] = row

    if o.llm and undecided:  # optional, slow: only the top candidates
        undecided.sort(key=lambda d: (not F.hosts[d]["via_url"], not F.hosts[d]["api"], -F.hosts[d]["count"]))
        send = undecided[:o.max_llm]
        print(f"[*] {name}: Llama classifying top {len(send)} of {len(undecided)} unknown domains")
        for d, (cat, conf, _) in llm.classify(o.ollama, o.model, name, package, send).items():
            rows[d].update(category=cat, confidence=conf, reason="llm")

    known = {d for d, r in rows.items() if r["category"] in ("first_party", "same_company")}
    if o.expand:
        for base in sorted({rules.registered_domain(d) for d in known}):
            for sub in expand.crtsh(base):
                rows.setdefault(sub, dict(domain=sub, category="first_party", confidence=0.8, reason=f"crt.sh {base}",
                                          is_api=bool(rules.host_api_hint(sub)), api_evidence="", sample_paths="",
                                          source="crtsh"))
    final = []
    for r in rows.values():
        r["registered_domain"] = rules.registered_domain(r["domain"])
        r["related"] = r["category"] in RELATED
        final.append(r)
    final.sort(key=lambda r: (not r["related"], not r["is_api"], r["category"], r["domain"]))
    return final, sorted(F.endpoints)


def process_app(name, package, platform, o, out_root: Path, local_file=None):
    """Returns (display_name, sorted related domains) or None if skipped."""
    if not package:
        package = downloader.resolve_package(name)
    label = name or package
    txt = out_root / f"{safe_name(label)}.txt"
    if o.resume and txt.exists():
        print(f"[*] {label}: skipped (already done)")
        return None
    src = local_file or downloader.download(package, Path(o.downloads), platform)
    work = Path(o.downloads) / "_unpacked" / package
    apks = downloader.prepare(src, work)
    if not name and platform == "android":
        label = extractor.get_package(apks[0])[1] or package
        txt = out_root / f"{safe_name(label)}.txt"
    final, endpoints = analyze(apks, label, package, o)

    related = sorted({r["domain"] for r in final if r["related"]})
    out_root.mkdir(parents=True, exist_ok=True)
    txt.write_text("\n".join(related) + ("\n" if related else ""))
    if o.full_report:
        d = out_root / "_full_reports" / safe_name(label)
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "domains.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(final)
        (d / "endpoints.json").write_text(json.dumps(endpoints, indent=2))
    print(f"[+] {label}: {len(related)} related domains -> {txt}")
    return label, related
