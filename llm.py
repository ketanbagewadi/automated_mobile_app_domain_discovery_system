"""Local LLM (Ollama) client: domain classification + related-domain suggestions."""
from progress import log
import json
import urllib.request

CATEGORIES = ["first_party", "same_company", "cdn_infra", "third_party_sdk", "unrelated"]


class OllamaError(RuntimeError):
    pass


def _post(host, path, payload, timeout):
    req = urllib.request.Request(host.rstrip("/") + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def check(host: str, model: str):
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=5) as r:
            names = [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception as e:
        raise OllamaError(f"Cannot reach Ollama at {host} ({e}). Start it with: ollama serve")
    if not any(n == model or n.split(":")[0] == model.split(":")[0] and ":" not in model for n in names):
        raise OllamaError(f"Model '{model}' not found. Installed: {names}. Run: ollama pull {model}")


def chat_json(host, model, system, user, timeout=600) -> dict:
    out = _post(host, "/api/chat", {
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": 0, "num_ctx": 8192},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }, timeout)
    text = out["message"]["content"]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        return json.loads(text[s:e + 1]) if s != -1 and e > s else {}


SYSTEM = "You are a network-forensics analyst. Reply with valid JSON only. Never invent facts."


def classify(host, model, app_name, package, domains, batch=40):
    """Return {domain: (category, confidence, reason)}. Compact JSON output keeps each call fast."""
    result = {}
    total = (len(domains) + batch - 1) // batch
    for n, i in enumerate(range(0, len(domains), batch), 1):
        chunk = domains[i:i + batch]
        prompt = f"""Mobile app: "{app_name}" (package: {package})
Classify each domain found inside its APK relative to this app.

Categories: first_party (app's own company/brand), same_company (other domain of the same parent company),
cdn_infra (CDN/cloud/edge serving this app), third_party_sdk (analytics, ads, crash, social login, payments),
unrelated (libraries, docs, standards, test domains).

Domains:
{json.dumps(chunk)}

Return JSON mapping every domain to one category, e.g. {{"example.com":"unrelated"}}"""
        try:
            data = chat_json(host, model, SYSTEM, prompt, timeout=300)
        except Exception as e:
            log(f"[!] LLM batch {n}/{total} failed: {e}")
            data = {}
        data = data.get("results", data) if isinstance(data, dict) else {}
        if isinstance(data, list):  # tolerate [{"domain":..,"category":..}]
            data = {str(r.get("domain", "")).lower(): r.get("category") for r in data if isinstance(r, dict)}
        for d, cat in data.items():
            d = str(d).lower().strip()
            if d in chunk and cat in CATEGORIES:
                result[d] = (cat, 0.7, "")
        log(f"    llm batch {n}/{total} done ({len(result)} classified)", flush=True)
    return result


def suggest(host, model, app_name, package, known_related, limit=40):
    """Ask the LLM for other domains the app's company likely uses. Must be DNS-verified by caller."""
    prompt = f"""App: "{app_name}" (package: {package})
Domains already known to be related: {json.dumps(sorted(known_related)[:60])}

List additional registered domains or hostnames this app's company very likely owns or uses
(brand domains, API hosts, regional TLD variants, CDN/edge hosts). Only include domains you are
confident really exist. Max {limit}.
Return JSON: {{"domains":["example.com", "..."]}}"""
    data = chat_json(host, model, SYSTEM, prompt)
    out = []
    for d in data.get("domains", []):
        d = str(d).lower().strip().strip(".")
        if "." in d and " " not in d and "/" not in d:
            out.append(d)
    return out[:limit]
