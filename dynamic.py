"""Runtime capture: run the app on an emulator/device via adb while PCAPdroid records traffic,
then extract DNS names + TLS SNI + HTTP hosts from the pcap with tshark.

One-time setup on the device/emulator:
  1. adb install PCAPdroid (com.emanuelef.remote_capture)
  2. Open it once, grant the VPN permission, Settings -> enable 'Control permissions' / API,
     copy the API key (or approve the capture prompt the first time).
"""
from progress import log
import shutil
import subprocess
import time
from pathlib import Path

import extractor

PCAPDROID = "com.emanuelef.remote_capture"


def adb(*args, timeout=120, check=False):
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout, check=check)


def parse_pcap(pcap: Path, F: extractor.Findings) -> int:
    if not shutil.which("tshark"):
        raise RuntimeError("tshark not found (install Wireshark/tshark) to parse pcaps")
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", "dns.flags.response==0 || tls.handshake.type==1 || http.host",
         "-T", "fields", "-e", "dns.qry.name", "-e", "tls.handshake.extensions_server_name", "-e", "http.host"],
        capture_output=True, text=True, timeout=300).stdout
    n = 0
    for line in out.splitlines():
        for field in line.split("\t"):
            for tok in field.split(","):
                host = extractor.clean_host(tok.strip().encode(), True)
                if host:
                    F.add(host, "dynamic", True)
                    n += 1
    return n


def capture(apks: list, package: str, F: extractor.Findings, api_key: str = "", seconds: int = 90, events: int = 400):
    if not shutil.which("adb"):
        raise RuntimeError("adb not found. Start an emulator/device and install Android platform-tools")
    if "device" not in adb("devices").stdout.split("\n", 1)[1]:
        raise RuntimeError("No adb device/emulator connected")
    name = f"cap_{package}_{int(time.time())}.pcap"

    log(f"[*] Installing {package} on device ...")
    if len(apks) == 1:
        adb("install", "-r", "-g", str(apks[0]), timeout=300)
    else:
        adb("install-multiple", "-r", "-g", *[str(a) for a in apks], timeout=300)

    key = ["-e", "api_key", api_key] if api_key else []
    adb("shell", "am", "start", "-n", f"{PCAPDROID}/.activities.CaptureCtrl", "-e", "action", "start", *key,
        "-e", "pcap_dump_mode", "pcap_file", "-e", "app_filter", package, "-e", "pcap_name", name)
    time.sleep(4)

    log(f"[*] Exercising app (monkey, {events} events) ...")
    adb("shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
    time.sleep(8)
    adb("shell", "monkey", "-p", package, "--throttle", "500", "--pct-syskeys", "0",
        "--ignore-crashes", "--ignore-timeouts", str(events), timeout=seconds + 120)
    time.sleep(max(0, seconds - events * 0.5))

    adb("shell", "am", "start", "-n", f"{PCAPDROID}/.activities.CaptureCtrl", "-e", "action", "stop", *key)
    time.sleep(4)

    local = Path(f"/tmp/{name}")
    r = adb("pull", f"/sdcard/Download/PCAPdroid/{name}", str(local))
    if not local.exists():
        raise RuntimeError(f"Could not pull pcap ({r.stderr.strip()}). Check PCAPdroid output path / API permission")
    n = parse_pcap(local, F)
    log(f"[*] Runtime capture: {n} host observations")
