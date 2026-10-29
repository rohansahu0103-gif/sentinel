"""Checks whether a link really exists: sends a safe HEAD request (GET fallback), reads only the status code."""
import socket
import time
from urllib.parse import urlparse

import requests

from scanner.domain_intel import _private

_cache, _online_at = {}, [0.0, False]
HEADERS = {"User-Agent": "Mozilla/5.0 (Sentinel link checker)"}


def _online():
    if time.time() - _online_at[0] < 30:
        return _online_at[1]
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        ok = True
    except OSError:
        ok = False
    _online_at[:] = [time.time(), ok]
    return ok


def check(url):
    """Returns (state, http_code). state: live | missing | down | unknown."""
    if url in _cache:
        return _cache[url]
    host = urlparse(url).hostname
    if not host or _private(host):
        return "unknown", None
    res = ("unknown", None)
    try:
        r = requests.head(url, timeout=5, allow_redirects=True, headers=HEADERS)
        if r.status_code in (400, 403, 405, 501, 999):
            r = requests.get(url, timeout=5, allow_redirects=True, headers=HEADERS, stream=True)
            r.close()
        res = ("missing", r.status_code) if r.status_code in (404, 410) else ("live", r.status_code)
    except requests.exceptions.SSLError:
        res = ("live", None)                       # server answered, certificate is the problem
    except requests.exceptions.ConnectionError:
        res = ("down", None) if _online() else ("unknown", None)
    except Exception:
        pass
    if res[0] != "unknown":
        _cache[url] = res
    return res
