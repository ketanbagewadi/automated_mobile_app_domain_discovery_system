"""Local LLM (Ollama) client: domain classification + related-domain suggestions."""
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


def classify(host, model, app_name, package, domains, batch=25):
    """Return {domain: (category, confidence, reason)}."""
    result = {}
    for i in range(0, len(domains), batch):
        chunk = domains[i:i + batch]
        prompt = f"""Mobile app: "{app_name}" (package: {package})
Classify each domain found inside its APK relative to this app.

Categories:
- first_party: domain run by the app's own company/brand (APIs, websites, regional variants)
- same_company: other domain owned by the same parent company
- cdn_infra: CDN / cloud / edge hostnames likely serving this app
- third_party_sdk: analytics, ads, crash reporting, social login, payments SDKs
- unrelated: libraries, docs links, standards, test/sample domains

Domains:
{json.dumps(chunk)}

Return JSON: {{"results":[{{"domain":"...","category":"<one category>","confidence":0.0-1.0,"reason":"<max 10 words>"}}]}}"""
        try:
            data = chat_json(host, model, SYSTEM, prompt)
        except Exception as e:
            print(f"[!] LLM batch failed: {e}")
            data = {}
        for r in data.get("results", []):
            d = str(r.get("domain", "")).lower().strip()
            cat = r.get("category")
            if d in chunk and cat in CATEGORIES:
                try:
                    conf = float(r.get("confidence", 0.5))
                except (TypeError, ValueError):
                    conf = 0.5
                result[d] = (cat, max(0.0, min(conf, 1.0)), str(r.get("reason", ""))[:120])
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
