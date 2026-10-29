"""Phishing URL detector: weighted heuristic features -> risk score (0-100).
Swap this for a trained ML model (see README) when you have a dataset."""
import math
import re
import socket
import threading
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
BAD_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov", "support", "work"}
KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "wallet", "password",
            "signin", "confirm", "suspend", "paypal", "upi", "kyc", "free", "gift", "otp"]
BRANDS = ["google", "paypal", "amazon", "apple", "microsoft", "facebook", "instagram",
          "netflix", "sbi", "hdfc", "icici", "paytm", "whatsapp"]

_dns_cache = {}


def _resolves(host, timeout=3):
    out = [None]

    def run():
        try:
            socket.getaddrinfo(host, None)
            out[0] = True
        except socket.gaierror:
            out[0] = False
        except Exception:
            out[0] = None
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return out[0]


def dns_status(host):
    """True = exists, False = does not exist, None = unknown (for example no internet)."""
    if host in _dns_cache:
        return _dns_cache[host]
    r = _resolves(host)
    if r is False and _resolves("example.com") is not True:
        return None                       # we are offline, so do not blame the link
    if r is not None:
        _dns_cache[host] = r
    return r


def invalid_reason(raw, parsed):
    """Returns why the link is not a valid web address, or None if its format is fine."""
    if re.search(r"\s", raw):
        return "The link contains spaces"
    if parsed.scheme not in ("http", "https", "ftp"):
        return f"Unsupported link type '{parsed.scheme}'"
    host = parsed.hostname
    if not host:
        return "No domain name found after the protocol"
    try:
        parsed.port
    except ValueError:
        return "The port number is not valid"
    if re.fullmatch(r"[\d.]+", host):
        octets = host.split(".")
        ok = len(octets) == 4 and all(o.isdigit() and int(o) <= 255 for o in octets)
        return None if ok else f"'{host}' is not a valid IP address"
    try:
        host = host.encode("idna").decode()
    except UnicodeError:
        return "The domain contains characters that cannot be used"
    labels = host.split(".")
    if host != "localhost" and len(labels) < 2:
        return f"'{host}' is not a full domain name (it needs an ending like .com or .in)"
    if len(host) > 253 or any(not l or len(l) > 63 or not re.fullmatch(r"[a-z0-9-]+", l) or l[0] == "-" or l[-1] == "-" for l in labels):
        return "The domain name has empty parts or invalid characters"
    tld = labels[-1]
    if host != "localhost" and not (re.fullmatch(r"[a-z]{2,24}", tld) or tld.startswith("xn--")):
        return f"'.{tld}' is not a valid domain ending"
    return None


def _entropy(text):
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def analyze_url(url, deep=False):
    url = url.strip()
    assumed = not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
    if assumed:
        url = "https://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host
    bad = invalid_reason(url, parsed)
    if bad:
        return {"type": "url", "target": url, "score": 0, "verdict": "invalid", "reasons": [
            {"points": 0, "text": bad}, {"points": 0, "text": "Check the spelling. A valid link looks like https://example.com"}]}
    reasons, score = ([{"points": 0, "text": "No protocol was typed, so https:// was assumed"}] if assumed else []), 0

    def hit(points, text):
        nonlocal score
        score += points
        reasons.append({"points": points, "text": text})

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        hit(30, "Uses a raw IP address instead of a domain name")
    if parsed.scheme != "https":
        hit(12, "Connection is not encrypted (no HTTPS)")
    if "@" in url:
        hit(20, "Contains '@', which can hide the real destination")
    if len(url) > 75:
        hit(10, f"Very long URL ({len(url)} characters)")
    if len(parts) > 4:
        hit(14, f"Too many subdomains ({len(parts) - 2})")
    if host.count("-") >= 2:
        hit(8, "Many hyphens in the domain name")
    if tld in BAD_TLDS:
        hit(15, f"Domain ending '.{tld}' is often abused for phishing")
    if base in SHORTENERS:
        hit(15, "Link shortener hides the final destination")
    if "xn--" in host:
        hit(20, "Punycode domain (possible look-alike characters)")
    found = [k for k in KEYWORDS if k in url.lower()]
    if found:
        hit(min(18, 6 * len(found)), "Sensitive words in URL: " + ", ".join(found[:4]))
    for brand in BRANDS:
        if brand in host and base.split(".")[0] != brand:
            hit(25, f"Brand name '{brand}' used on an unrelated domain")
            break
    if _entropy(host) > 3.8 and len(host) > 15:
        hit(10, "Domain looks randomly generated")
    if parsed.port and parsed.port not in (80, 443):
        hit(8, f"Unusual port {parsed.port}")
    if url.count("//") > 1:
        hit(8, "Embedded redirect ('//' appears twice)")

    dead, dns = False, None
    if not re.fullmatch(r"[\d.]+", host) and host != "localhost":
        dns = dns_status(host)
    if dns is False:
        dead = True
        reasons.append({"points": 0, "text": "Domain not found in DNS: the site does not exist or has been taken down"})
    live, code = "unknown", None
    if dns is False:
        live = "missing"
    else:
        from scanner import liveness
        live, code = liveness.check(url)
        if live == "missing":
            dead = True
            reasons.append({"points": 0, "text": f"This link does not exist: the server replied 'Not Found' (HTTP {code})"})
        elif live == "down":
            dead = True
            reasons.append({"points": 0, "text": "This link cannot be reached: the website is offline or refuses connections"})
        elif live == "unknown":
            reasons.append({"points": 0, "text": "Could not verify that this link exists (no response, private address or no internet)"})
    from scanner import domain_intel, ml_model, reputation
    ml = ml_model.predict(url)
    if ml is not None:
        score = round(0.5 * score + 50 * ml)
        reasons.append({"points": round(50 * ml), "text": f"ML model estimates {ml * 100:.0f}% phishing probability"})
    for pts, txt in reputation.check_url(url):
        score = max(score, pts)
        reasons.append({"points": pts, "text": txt})
    if deep:
        for pts, txt in domain_intel.check(url, host):
            score += pts
            reasons.append({"points": pts, "text": txt})
    score = min(score, 100)
    verdict = "malicious" if score >= 55 else "suspicious" if score >= 25 else "safe"
    if dead and verdict == "safe":
        verdict = "invalid"
    if not dead and not any(r["points"] for r in reasons):
        reasons.insert(0, {"points": 0, "text": "No phishing indicators found"})
    details = {"Protocol": parsed.scheme.upper(), "Domain": host, "Ending": "." + tld if "." in host else "-", "Path": parsed.path or "/",
               "Link status": {"live": f"Exists (HTTP {code})" if code else "Exists", "missing": f"Not found (HTTP {code})" if code else "Domain not found", "down": "Unreachable", "unknown": "Not verified"}[live],
               "Domain lookup": "IP address" if re.fullmatch(r"[\d.]+", host) else {True: "Domain exists", False: "Domain not found", None: "Not checked"}[dns]}
    return {"type": "url", "target": url, "score": score, "verdict": verdict, "reasons": reasons, "details": details}
