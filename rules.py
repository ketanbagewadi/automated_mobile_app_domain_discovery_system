"""Rule-based helpers: registered-domain parsing, noise/SDK/CDN lists, brand matching, API hints."""
import re

SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}

NOISE = {
    "schemas.android.com", "www.w3.org", "w3.org", "apache.org", "www.apache.org",
    "xmlpull.org", "www.xmlpull.org", "localhost", "example.com", "www.example.com",
    "developer.android.com", "source.android.com", "schema.org", "json.org",
    "ietf.org", "www.ietf.org", "gnu.org", "www.gnu.org", "iana.org", "unicode.org",
    "openssl.org", "kotlinlang.org", "xml.org", "java.sun.com", "sun.com",
    "creativecommons.org", "purl.org", "ns.adobe.com", "dublincore.org", "github.com",
    "stackoverflow.com", "mozilla.org", "www.mozilla.org", "eclipse.org", "jetbrains.com",
    "connectivitycheck.gstatic.com", "time.android.com", "clients3.google.com",
    "ocsp.digicert.com", "crl.microsoft.com", "ocsp.pki.goog",
}

SDK_SUFFIXES = (
    "google-analytics.com", "googleapis.com", "gstatic.com", "doubleclick.net",
    "googleadservices.com", "googlesyndication.com", "firebaseio.com", "firebaseapp.com",
    "firebase.com", "crashlytics.com", "app-measurement.com", "facebook.com", "fbcdn.net",
    "facebook.net", "appsflyer.com", "adjust.com", "adjust.io", "branch.io", "app.link",
    "amplitude.com", "mixpanel.com", "segment.io", "segment.com", "sentry.io",
    "bugsnag.com", "onesignal.com", "braze.com", "appboy.com", "unity3d.com", "applovin.com",
    "ironsrc.com", "mopub.com", "vungle.com", "chartboost.com", "inmobi.com", "adcolony.com",
    "flurry.com", "newrelic.com", "nr-data.net", "datadoghq.com", "stripe.com", "paypal.com",
    "braintreegateway.com", "twitter.com", "linkedin.com", "tiktok.com", "snapchat.com",
    "pinterest.com", "kochava.com", "singular.net", "moengage.com", "clevertap.com",
    "taboola.com", "outbrain.com", "criteo.com", "smaato.net", "pubmatic.com", "rubiconproject.com",
)

CDN_SUFFIXES = (
    "cloudfront.net", "e-msedge.net", "a-msedge.net", "b-msedge.net", "s-msedge.net",
    "akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net", "edgesuite.net", "akadns.net",
    "fastly.net", "fastlylb.net", "cloudflare.com", "cloudflare.net", "azureedge.net", "msedge.net",
    "azurefd.net", "trafficmanager.net", "windows.net", "amazonaws.com", "googleusercontent.com",
    "appspot.com", "herokuapp.com", "edgecastcdn.net", "b-cdn.net", "jsdelivr.net", "cdn77.org",
    "stackpathcdn.com",
)

GENERIC_TOKENS = {
    "com", "org", "net", "android", "app", "apps", "mobile", "free", "lite", "pro", "the",
    "www", "main", "client", "release", "beta", "official", "play", "store", "and", "for",
}

API_HOST_LABELS = {"api", "apis", "gw", "gateway", "graph", "rest", "rpc", "grpc", "ws", "wss",
                   "socket", "mqtt", "auth", "login", "oauth", "sso", "accounts", "identity", "mobile-api"}
API_PATH_RE = re.compile(r"(^|/)(api|rest|graphql|rpc|gateway|v\d+(\.\d+)?|oauth2?|auth|token|login|ws|socket|mobile)(/|$|\?)", re.I)


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _matches(host: str, suffixes) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def is_noise(host: str) -> bool:
    return host in NOISE or any(host.endswith("." + n) for n in NOISE)


def brand_tokens(app_name, package) -> set:
    tokens = set()
    for src in (app_name or "", (package or "").replace(".", " ")):
        for t in re.split(r"[^a-zA-Z0-9]+", src.lower()):
            if len(t) >= 4 and t not in GENERIC_TOKENS:
                tokens.add(t)
    return tokens


def rule_classify(host: str, tokens: set):
    """Return (category, confidence, reason) or None if undecided (-> LLM)."""
    reg_label = registered_domain(host).split(".")[0]
    for t in tokens:
        if t in reg_label:
            return "first_party", 0.9, f"brand token '{t}' in domain"
    if _matches(host, SDK_SUFFIXES):
        return "third_party_sdk", 0.9, "known SDK/analytics/ads domain"
    if _matches(host, CDN_SUFFIXES):
        return "cdn_infra", 0.85, "known CDN/cloud infrastructure"
    return None


def host_api_hint(host: str):
    first = host.split(".")[0]
    if first in API_HOST_LABELS or first.startswith("api-") or first.startswith("api."):
        return f"host-label:{first}"
    return None
