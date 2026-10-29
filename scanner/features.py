"""URL -> numeric features, shared by training and prediction."""
import math
import re
from urllib.parse import urlparse

KW = ["login", "verify", "update", "secure", "account", "bank", "wallet", "password", "signin", "confirm", "paypal", "free", "gift", "otp", "kyc"]
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}


def _ent(t):
    return -sum(t.count(c) / len(t) * math.log2(t.count(c) / len(t)) for c in set(t)) if t else 0.0


def extract(url):
    url = url.strip()
    p = urlparse(url if "://" in url else "http://" + url)
    host, path = (p.hostname or "").lower(), p.path or ""
    parts = host.split(".")
    return [len(url), len(host), host.count("."), host.count("-"), sum(c.isdigit() for c in url) / max(len(url), 1),
            sum(url.count(c) for c in "@?=&%_~"), int(bool(re.fullmatch(r"[\d.]+", host))), int(p.scheme == "https"),
            max(len(parts) - 2, 0), len(path), len(p.query), sum(k in url.lower() for k in KW), _ent(host),
            len(parts[-1]) if parts else 0, int(p.port not in (None, 80, 443)), int(".".join(parts[-2:]) in SHORT),
            url.count("//") - 1, path.count("/")]
