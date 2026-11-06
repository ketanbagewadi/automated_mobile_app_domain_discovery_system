"""Reassemble/decompile with apktool (smali + decoded XML) and jadx (Java source)."""
from progress import log
import shutil
import subprocess
import tempfile
from pathlib import Path

import extractor


def tools():
    return {t: bool(shutil.which(t)) for t in ("apktool", "jadx")}


def _run(cmd, timeout):
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log(f"[!] timeout: {cmd[0]}")


def run(apk: Path, F: extractor.Findings, use_apktool=True, use_jadx=True, jadx_timeout=1500):
    t = tools()
    if use_apktool:
        if t["apktool"]:
            with tempfile.TemporaryDirectory() as tmp:
                log(f"[*] apktool decoding {apk.name} ...")
                _run(["apktool", "d", "-f", "-o", tmp, str(apk)], 900)
                extractor.scan_dir(Path(tmp), "apktool", F)
        else:
            log("[!] apktool not installed - skipping smali/XML decode")
    if use_jadx:
        if t["jadx"]:
            with tempfile.TemporaryDirectory() as tmp:
                log(f"[*] jadx decompiling {apk.name} (can take minutes) ...")
                _run(["jadx", "-q", "-j", "4", "-d", tmp, str(apk)], jadx_timeout)  # non-zero exit is normal
                extractor.scan_dir(Path(tmp), "jadx", F)
        else:
            log("[!] jadx not installed - skipping Java decompile (string-concat URLs / Retrofit endpoints will be missed)")
