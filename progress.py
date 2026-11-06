"""Thread-safe progress tracking + timestamped, app-tagged logging."""
import threading
import time

_lock = threading.Lock()
_local = threading.local()
_s = {"total": 0, "ok": 0, "skipped": 0, "failed": 0, "start": time.time(), "active": {}}


def _fmt(sec):
    sec = int(sec)
    return f"{sec // 3600:d}:{sec % 3600 // 60:02d}:{sec % 60:02d}" if sec >= 3600 else f"{sec // 60:02d}:{sec % 60:02d}"


def init(total):
    with _lock:
        _s.update(total=total, ok=0, skipped=0, failed=0, start=time.time(), active={})


def finished():
    return _s["ok"] + _s["skipped"] + _s["failed"]


def log(msg="", **_):
    app = getattr(_local, "app", None)
    stamp = time.strftime("%H:%M:%S")
    tag = f" [{app}]" if app else ""
    with _lock:
        print(f"{stamp} [{finished()}/{_s['total']}]{tag} {msg}", flush=True)


def start(app):
    _local.app = app
    with _lock:
        _s["active"][app] = time.time()
    log("started")


def stage(text):
    """Report what the current app is doing right now."""
    app = getattr(_local, "app", None)
    with _lock:
        if app in _s["active"]:
            _s["active"][app] = time.time()
    log(text)


def done(app, status, detail=""):
    """status: ok | skipped | failed. Prints the overall status line."""
    with _lock:
        _s[status] += 1
        _s["active"].pop(app, None)
        fin, total = finished(), _s["total"]
        elapsed = time.time() - _s["start"]
        remaining = total - fin
        eta = _fmt(elapsed / fin * remaining) if fin and remaining else "--"
        active = ", ".join(_s["active"]) or "-"
        icon = {"ok": "OK  ", "skipped": "SKIP", "failed": "FAIL"}[status]
        print(f"{time.strftime('%H:%M:%S')} [{fin}/{total}] {icon} {app} {detail}\n"
              f"           progress: {_s['ok']} ok | {_s['skipped']} skipped | {_s['failed']} failed | "
              f"{remaining} remaining | running: {active} | elapsed {_fmt(elapsed)} | ETA {eta}", flush=True)
