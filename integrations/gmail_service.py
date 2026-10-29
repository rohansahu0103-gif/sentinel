"""Gmail OAuth (web flow) + inbox scanner: headers (SPF/DKIM/DMARC, Reply-To), links, attachments."""
import base64, os, re, threading, time

from scanner.file_scanner import scan_bytes
from scanner.url_detector import analyze_url

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
REDIRECT = "http://127.0.0.1:5000/gmail/callback"
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))   # project folder, works from any terminal location
CREDS, TOKEN = os.path.join(_ROOT, "credentials.json"), os.path.join(_ROOT, "token.json")
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")   # localhost only
state = {"email": None, "last_scan": None, "emails": 0, "error": None}
_flow, _seen, _started = None, set(), False


def has_libs():
    try:
        import googleapiclient, google_auth_oauthlib  # noqa
        return True
    except ImportError:
        return False


def status():
    return {"libs": has_libs(), "credentials": os.path.exists(CREDS), "connected": os.path.exists(TOKEN), **state}


def auth_url():
    global _flow
    from google_auth_oauthlib.flow import Flow
    _flow = Flow.from_client_secrets_file(CREDS, SCOPES, redirect_uri=REDIRECT)
    return _flow.authorization_url(access_type="offline", prompt="consent")[0]


def finish_auth(response_url):
    _flow.fetch_token(authorization_response=response_url)
    open(TOKEN, "w").write(_flow.credentials.to_json())


def disconnect():
    if os.path.exists(TOKEN):
        os.remove(TOKEN)
    state.update(email=None, error=None)
    _seen.clear()


def _service():
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)
    if not creds.valid and creds.refresh_token:
        creds.refresh(Request())
        open(TOKEN, "w").write(creds.to_json())
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _walk(parts):
    for p in parts or []:
        yield p
        yield from _walk(p.get("parts"))


def check_headers(h):
    reasons, score = [], 0
    auth = h.get("authentication-results", "").lower()
    for k in ("spf", "dkim", "dmarc"):
        if f"{k}=fail" in auth or f"{k}=softfail" in auth:
            score += 20
            reasons.append({"points": 20, "text": f"{k.upper()} check failed: sender may be forged"})
    a, b = re.search(r"@([\w.-]+)", h.get("from", "")), re.search(r"@([\w.-]+)", h.get("reply-to", ""))
    if a and b and a.group(1).lower() != b.group(1).lower():
        score += 25
        reasons.append({"points": 25, "text": f"Reply-To domain ({b.group(1)}) differs from sender ({a.group(1)})"})
    return score, reasons


def scan_inbox(log):
    try:
        svc = _service()
        state["email"] = svc.users().getProfile(userId="me").execute()["emailAddress"]
        for m in svc.users().messages().list(userId="me", q="newer_than:7d", maxResults=15).execute().get("messages", []):
            if m["id"] in _seen:
                continue
            _seen.add(m["id"])
            state["emails"] += 1
            full = svc.users().messages().get(userId="me", id=m["id"]).execute()
            h = {x["name"].lower(): x["value"] for x in full["payload"].get("headers", [])}
            score, reasons = check_headers(h)
            log({"type": "email", "target": f'{h.get("subject", "(no subject)")} | {h.get("from", "")}', "score": min(score, 100),
                 "verdict": "malicious" if score >= 60 else "suspicious" if score >= 20 else "safe",
                 "reasons": reasons or [{"points": 0, "text": "Sender checks passed"}]}, "gmail")
            for part in _walk([full["payload"]]):
                body = part.get("body", {})
                if part.get("filename") and body.get("attachmentId"):
                    att = svc.users().messages().attachments().get(userId="me", messageId=m["id"], id=body["attachmentId"]).execute()
                    log(scan_bytes(part["filename"], base64.urlsafe_b64decode(att["data"])), "gmail")
                elif part.get("mimeType") == "text/plain" and body.get("data"):
                    text = base64.urlsafe_b64decode(body["data"]).decode("utf-8", "ignore")
                    for url in set(re.findall(r"https?://[^\s<>\"]+", text)):
                        log(analyze_url(url), "gmail")
        state.update(last_scan=time.strftime("%H:%M:%S"), error=None)
    except Exception as exc:
        state["error"] = str(exc)[:200]


def start_polling(log, every=60):
    global _started
    if _started:
        return
    _started = True

    def loop():
        while True:
            if os.path.exists(TOKEN):
                scan_inbox(log)
            time.sleep(every)
    threading.Thread(target=loop, daemon=True).start()
