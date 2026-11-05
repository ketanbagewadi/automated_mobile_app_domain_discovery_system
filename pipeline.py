"""Per-app pipeline: download -> unpack -> static + decompile (+ runtime) -> classify -> expand -> save."""
import csv
import json
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


def analyze(apks, name, package, o):
    F = extractor.Findings()
    for apk in apks:
        print(f"[*] Static scan: {apk.name}")
        extractor.scan_zip(apk, F)
        if not o.no_decompile:
            decompile.run(apk, F, use_apktool=not o.no_apktool, use_jadx=not o.no_jadx)

    if getattr(o, "pcap", None):
        dynamic.parse_pcap(Path(o.pcap), F)
    if getattr(o, "dynamic", False):
        try:
            dynamic.capture(apks, package, F, o.pcapdroid_key, o.run_seconds, o.events)
        except Exception as e:
            print(f"[!] runtime capture failed: {e}")
    print(f"[*] Raw hostnames: {len(F.hosts)} | Retrofit endpoints: {len(F.endpoints)}")

    tokens = rules.brand_tokens(name, package)
    rows, undecided = {}, []
    for host, info in sorted(F.hosts.items()):
        if rules.is_noise(host):
            continue
        row = dict(domain=host, category="unknown", confidence=0.0, reason="",
                   is_api=bool(info["api"]), api_evidence=";".join(sorted(info["api"]))[:150],
                   sample_paths=" ".join(sorted(info["paths"])[:5]),
                   source=",".join(sorted(info["sources"])))
        r = rules.rule_classify(host, tokens)
        if r:
            row.update(category=r[0], confidence=r[1], reason=r[2])
        else:
            undecided.append(host)
        rows[host] = row

    if not o.no_llm and undecided:
        print(f"[*] {o.model}: classifying {len(undecided)} domains ...")
        for d, (cat, conf, why) in llm.classify(o.ollama, o.model, name, package, undecided).items():
            rows[d].update(category=cat, confidence=conf, reason="llm: " + why)

    known = {d for d, r in rows.items() if r["category"] in ("first_party", "same_company")}

    if not o.no_llm and o.suggest:
        print("[*] LLM suggestions (DNS-verified) ...")
        try:
            for d in llm.suggest(o.ollama, o.model, name, package, known):
                if d not in rows and expand.resolves(d):
                    rows[d] = dict(domain=d, category="same_company", confidence=0.5, reason="llm suggestion, DNS resolves",
                                   is_api=bool(rules.host_api_hint(d)), api_evidence=rules.host_api_hint(d) or "",
                                   sample_paths="", source="llm_suggested")
        except Exception as e:
            print(f"[!] suggest failed: {e}")

    if o.expand:
        print("[*] crt.sh expansion ...")
        for base in sorted({rules.registered_domain(d) for d in known}):
            for sub in expand.crtsh(base):
                if sub not in rows:
                    rows[sub] = dict(domain=sub, category="first_party", confidence=0.8, reason=f"cert transparency: {base}",
                                     is_api=bool(rules.host_api_hint(sub)), api_evidence=rules.host_api_hint(sub) or "",
                                     sample_paths="", source="crtsh")

    final = []
    for r in rows.values():
        r["registered_domain"] = rules.registered_domain(r["domain"])
        r["related"] = r["category"] in RELATED
        final.append(r)
    final.sort(key=lambda r: (not r["related"], not r["is_api"], r["category"], r["domain"]))
    return final, sorted(F.endpoints)


def save(final, endpoints, name, package, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "domains.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(final)
    (out_dir / "domains.json").write_text(json.dumps(
        {"app": name, "package": package, "domains": final, "retrofit_endpoints": endpoints}, indent=2, default=list))


def print_summary(final):
    rel = [r for r in final if r["related"]]
    print(f"[+] {len(rel)} related domains / {len(final)} total | API hosts: {sum(r['is_api'] for r in rel)}")
    for r in rel[:40]:
        print(f"    {r['category']:<13} {'API' if r['is_api'] else '   '} {r['confidence']:.2f}  {r['domain']}")
    if len(rel) > 40:
        print(f"    ... +{len(rel) - 40} more in CSV")


def process_app(name, package, platform, o, out_root: Path, local_file: Path | None = None):
    """Full pipeline for one app. Returns final rows."""
    if not package:
        package = downloader.resolve_package(name)
        print(f"[*] Resolved '{name}' -> {package}")
    out_dir = out_root / package
    if o.resume and (out_dir / "domains.csv").exists():
        print(f"[*] Skipping {package} (already done)")
        return None
    src = local_file or downloader.download(package, Path(o.downloads), platform)
    apks = downloader.prepare(src, out_dir / "_unpacked")
    detected_pkg, label = extractor.get_package(apks[0]) if platform == "android" else (None, None)
    name = name or label or package
    print(f"[*] {name} | {package} | {len(apks)} APK file(s)")
    final, endpoints = analyze(apks, name, package, o)
    save(final, endpoints, name, package, out_dir)
    print_summary(final)
    return final
