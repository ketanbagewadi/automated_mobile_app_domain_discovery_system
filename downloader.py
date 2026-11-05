"""Download APK/IPA by package id (apkeep -> APKPure fallback) and unpack bundles (xapk/apks)."""
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

EXTS = (".apk", ".xapk", ".apks", ".ipa")


def resolve_package(name: str) -> str:
    """App name -> Play Store package id (needs: pip install google-play-scraper)."""
    try:
        from google_play_scraper import search
    except ImportError:
        raise RuntimeError(f"No package id for '{name}'. Add a 'package' column or: pip install google-play-scraper")
    res = search(name, n_hits=1)
    if not res:
        raise RuntimeError(f"Play Store search found nothing for '{name}'")
    return res[0]["appId"]


def _existing(package: str, dest: Path):
    for p in sorted(dest.glob(package + "*")):
        if p.suffix.lower() in EXTS and zipfile.is_zipfile(p):
            return p
    return None


def download(package: str, dest: Path, platform: str = "android") -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    found = _existing(package, dest)
    if found:
        print(f"[*] Using cached download: {found.name}")
        return found

    if platform == "ios":
        if not shutil.which("ipatool"):
            raise RuntimeError("iOS needs ipatool (https://github.com/majd/ipatool) logged in: ipatool auth login")
        subprocess.run(["ipatool", "download", "-b", package, "-o", str(dest), "--purchase"], check=True, timeout=900)
        found = _existing(package, dest) or next(iter(sorted(dest.glob("*.ipa"))), None)
        if not found:
            raise RuntimeError("ipatool finished but no .ipa found")
        return found

    if shutil.which("apkeep"):
        r = subprocess.run(["apkeep", "-a", package, "-d", "apk-pure", str(dest)], capture_output=True, text=True, timeout=900)
        found = _existing(package, dest)
        if found:
            return found
        print(f"[!] apkeep failed: {(r.stderr or r.stdout).strip()[:200]}")

    url = f"https://d.apkpure.com/b/APK/{package}?version=latest"
    target = dest / f"{package}.apk"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13)"})
        with urllib.request.urlopen(req, timeout=120) as r, open(target, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception as e:
        target.unlink(missing_ok=True)
        raise RuntimeError(f"Download failed for {package}: {e}. Install apkeep or place the file in {dest}/")
    if not zipfile.is_zipfile(target):
        target.unlink(missing_ok=True)
        raise RuntimeError(f"Downloaded file for {package} is not a valid APK/zip")
    return target


def prepare(path: Path, workdir: Path) -> list:
    """If `path` is a plain APK/IPA return [path]; if it's a bundle (xapk/apks) unzip and return inner APKs."""
    if not zipfile.is_zipfile(path):
        raise ValueError(f"{path.name} is not a zip/APK")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "AndroidManifest.xml" in names or any(n.startswith("Payload/") for n in names):
            return [path]
        inner = [n for n in names if n.lower().endswith(".apk")]
        if not inner:
            raise ValueError(f"{path.name}: zip contains no APK")
        workdir.mkdir(parents=True, exist_ok=True)
        out = []
        for n in inner:
            z.extract(n, workdir)
            out.append(workdir / n)
    out.sort(key=lambda p: p.stat().st_size, reverse=True)  # base APK first
    return out
