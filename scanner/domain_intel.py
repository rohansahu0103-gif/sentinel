"""Deep checks: domain age (WHOIS), SSL certificate, redirect chain."""
import datetime
import ipaddress
import socket
import ssl
from urllib.parse import urlparse

import requests


def _private(host):
    try:
        return any((ipaddress.ip_address(i[4][0]).is_private or ipaddress.ip_address(i[4][0]).is_loopback) for i in socket.getaddrinfo(host, None))
    except Exception:
        return True


def check(url, host):
    if not host or _private(host):
        return [(0, "Deep scan skipped: host is private or does not resolve")]
    out = []
    try:
        import whois
        created = whois.whois(host).creation_date
        created = created[0] if isinstance(created, list) else created
        if created:
            age = (datetime.datetime.now() - created.replace(tzinfo=None)).days
            out.append((25, f"Domain registered only {age} days ago") if age < 30 else
                       (10, f"Domain is young ({age} days old)") if age < 180 else (0, f"Domain is {age // 365} years old"))
    except ImportError:
        out.append((0, "Domain age skipped: pip install python-whois"))
    except Exception:
        out.append((8, "Domain registration details are hidden or unavailable"))
    if url.startswith("https"):
        try:
            with socket.create_connection((host, 443), timeout=5) as s, ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
                issuer = dict(x[0] for x in t.getpeercert()["issuer"]).get("organizationName", "unknown")
                out.append((0, f"SSL certificate is valid (issued by {issuer})"))
        except ssl.SSLCertVerificationError:
            out.append((25, "SSL certificate is invalid or does not match the domain"))
        except Exception:
            pass
    try:
        r = requests.get(url, timeout=6, allow_redirects=True, stream=True, headers={"User-Agent": "Sentinel/1.0"})
        r.close()
        final = urlparse(r.url).hostname or ""
        if len(r.history) >= 3:
            out.append((10, f"Long redirect chain ({len(r.history)} hops)"))
        if final and final.split(".")[-2:] != host.split(".")[-2:]:
            out.append((15, f"Redirects to a different domain: {final}"))
    except Exception:
        out.append((5, "Site did not respond to a safe test request"))
    return out
