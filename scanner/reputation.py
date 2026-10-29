"""VirusTotal and Google Safe Browsing lookups (free API keys: VT_API_KEY, GSB_API_KEY)."""
import base64
import os

import requests


def _vt(path):
    key = os.getenv("VT_API_KEY")
    if not key:
        return None
    try:
        r = requests.get("https://www.virustotal.com/api/v3/" + path, headers={"x-apikey": key}, timeout=8)
        return r.json()["data"]["attributes"]["last_analysis_stats"] if r.status_code == 200 else None
    except Exception:
        return None


def check_url(url):
    out = []
    st = _vt("urls/" + base64.urlsafe_b64encode(url.encode()).decode().strip("="))
    if st:
        bad, total = st.get("malicious", 0) + st.get("suspicious", 0), sum(st.values())
        out.append((min(100, 55 + bad * 8) if bad else 0, f"VirusTotal: {bad} of {total} engines flag this link"))
    gk = os.getenv("GSB_API_KEY")
    if gk:
        try:
            body = {"client": {"clientId": "sentinel", "clientVersion": "1.0"}, "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
            r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gk}", json=body, timeout=8)
            if r.ok and r.json().get("matches"):
                out.append((95, "Google Safe Browsing lists this link as dangerous"))
        except Exception:
            pass
    return out


def check_file(sha256):
    st = _vt("files/" + sha256)
    if not st:
        return []
    bad, total = st.get("malicious", 0) + st.get("suspicious", 0), sum(st.values())
    return [(min(100, 60 + bad * 4) if bad else 0, f"VirusTotal: {bad} of {total} antivirus engines flag this file")]
