"""Sentinel - phishing, file and DDoS protection dashboard. Run: python app.py"""
import csv, importlib.util, io, os, random, time
from collections import Counter, deque

import requests
from flask import Flask, Response, jsonify, redirect, render_template, request

from integrations import gmail_service as gmail
from scanner import alerts, ml_model, sniffer

from scanner.file_scanner import scan_bytes
from scanner.firewall import Firewall
from scanner.url_detector import analyze_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # 50 MB upload limit
events = deque(maxlen=100)


def log_event(result, source="manual"):
    events.appendleft({**result, "source": source, "time": time.strftime("%H:%M:%S"), "ts": time.time()})
    if result.get("verdict") in ("malicious", "blocked") and not result.get("demo"):
        alerts.send(f"SENTINEL ALERT: {result['verdict'].upper()} {result['type']} (source: {source})\n{result['target']}\n"
                    f"Risk score {result['score']}/100\n{result['reasons'][0]['text']}")


firewall = Firewall(on_event=lambda e: log_event(e, source="firewall"))


@app.before_request
def ddos_guard():
    ip = request.remote_addr or "unknown"
    if not firewall.record(ip):
        return jsonify(error="Blocked by Sentinel firewall (too many requests)"), 429


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan-url")
def scan_url():
    url = (request.get_json(silent=True) or {}).get("url", "").strip()
    if not url:
        return jsonify(error="Please enter a URL"), 400
    result = analyze_url(url, deep=request.args.get("deep") == "1")
    log_event(result, request.args.get("source", "manual"))
    return jsonify(result)


@app.post("/api/scan-file")
def scan_file():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Please choose a file"), 400
    result = scan_bytes(f.filename, f.read())
    log_event(result, request.args.get("source", "manual"))
    return jsonify(result)


@app.get("/api/events")
def get_events():
    return jsonify(list(events))


@app.get("/api/firewall")
def fw_status():
    return jsonify(firewall.status())


@app.post("/api/firewall/simulate")
def fw_simulate():
    firewall.simulate_attack(sources=int(request.args.get("sources", 1)))
    return jsonify(ok=True)


@app.post("/api/firewall/unblock")
def fw_unblock():
    firewall.unblock((request.get_json(silent=True) or {}).get("ip", ""))
    return jsonify(ok=True)


WA_VERIFY_TOKEN = os.getenv("WA_VERIFY_TOKEN", "change-me")
WA_ACCESS_TOKEN = os.getenv("WA_ACCESS_TOKEN", "")

# ---- Dashboard data ----
@app.get("/api/stats")
def stats():
    ev, now = list(events), time.time()
    verdicts = Counter(e["verdict"] for e in ev)
    threats = verdicts["suspicious"] + verdicts["malicious"] + verdicts["blocked"]
    buckets = [{"total": 0, "threats": 0} for _ in range(12)]          # 12 x 5 minutes
    for e in ev:
        i = int((now - e["ts"]) // 300)
        if i < 12:
            buckets[11 - i]["total"] += 1
            buckets[11 - i]["threats"] += e["verdict"] != "safe"
    reasons = Counter(r["text"].split(":")[0].split("(")[0].strip() for e in ev if e["verdict"] != "safe" for r in e["reasons"][:2])
    penalty = 100 * (verdicts["malicious"] + 0.5 * verdicts["suspicious"] + 0.5 * verdicts["blocked"]) / max(len(ev), 1)
    return jsonify(total=len(ev), threats=threats, verdicts=verdicts, sources=Counter(e["source"] for e in ev),
                   types=Counter(e["type"] for e in ev), timeline=buckets, top_reasons=reasons.most_common(5),
                   score=max(0, round(100 - penalty)), blocked_ips=firewall.total_blocked)


@app.get("/api/export.csv")
def export_csv():
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "source", "type", "target", "verdict", "score", "top_reason"])
    for e in events:
        w.writerow([e["time"], e["source"], e["type"], e["target"], e["verdict"], e["score"], e["reasons"][0]["text"]])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=sentinel_report.csv"})


@app.post("/api/demo")
def demo():
    """Fills the dashboard with realistic sample activity (clearly tagged as demo)."""
    items = [("gmail", analyze_url("http://secure-paypal-login.verify-account.tk/signin")), ("gmail", analyze_url("https://github.com/")),
             ("whatsapp", analyze_url("http://bit.ly/free-gift-kyc")), ("whatsapp", analyze_url("http://192.168.4.7:8080/bank/otp")),
             ("gmail", scan_bytes("invoice.pdf.exe", b"MZ" + b"\0" * 300)), ("gmail", scan_bytes("report.pdf", b"%PDF-1.4 hello")),
             ("whatsapp", scan_bytes("photo.jpg", b"MZ" + b"powershell " * 5)), ("gmail", scan_bytes("notes.txt", b"meeting at 5")),
             ("manual", analyze_url("https://www.wikipedia.org")), ("gmail", scan_bytes("budget.xlsm", b"PK\x03\x04AutoOpen"))]
    for k in range(3):
        for src, res in items:
            log_event({**res, "demo": True}, src)
            events[0]["ts"] -= random.randint(0, 3300)
    firewall.simulate_attack(1)
    return jsonify(ok=True)


@app.post("/api/clear")
def clear():
    events.clear()
    return jsonify(ok=True)



# ---- QR code, engines, alerts, PDF report ----
@app.post("/api/scan-qr")
def scan_qr():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Please choose an image with a QR code"), 400
    try:
        import cv2, numpy as np
    except ImportError:
        return jsonify(error="QR scanning needs: pip install opencv-python-headless numpy"), 501
    img = cv2.imdecode(np.frombuffer(f.read(), np.uint8), cv2.IMREAD_COLOR)
    text = cv2.QRCodeDetector().detectAndDecode(img)[0] if img is not None else ""
    if not text:
        return jsonify(error="No QR code found. Try a sharper, closer image."), 400
    if text.lower().startswith(("http://", "https://", "www.")) or "." in text and " " not in text:
        result = analyze_url(text, deep=request.args.get("deep") == "1")
        result["reasons"].insert(0, {"points": 0, "text": "Link was hidden inside a QR code"})
    else:
        result = {"type": "url", "target": text[:200], "score": 0, "verdict": "safe",
                  "reasons": [{"points": 0, "text": "QR code holds plain text, not a link"}]}
    log_event(result, "qr")
    return jsonify(result)


def _has(mod):
    return importlib.util.find_spec(mod) is not None


@app.get("/api/engines")
def engines():
    m, a, fw = ml_model.metrics(), alerts.configured(), firewall.status()
    E = lambda name, on, detail: {"name": name, "on": on, "detail": detail}
    return jsonify([
        E("Rule-based link and file analysis", True, "Always on"),
        E("Machine learning phishing model", bool(m), f"Accuracy {m['accuracy'] * 100:.1f}% on {m['samples']} URLs, F1 {m['f1']:.2f}" if m else "Not trained. Run: python train_model.py dataset.csv"),
        E("VirusTotal (links and file hashes)", bool(os.getenv("VT_API_KEY")), "Active" if os.getenv("VT_API_KEY") else "Set environment variable VT_API_KEY"),
        E("Google Safe Browsing", bool(os.getenv("GSB_API_KEY")), "Active" if os.getenv("GSB_API_KEY") else "Set environment variable GSB_API_KEY"),
        E("Domain intelligence (age, SSL, redirects)", True, "Use the Deep scan option" + ("" if _has("whois") else ". Domain age needs: pip install python-whois")),
        E("QR code scanner", _has("cv2"), "Ready" if _has("cv2") else "pip install opencv-python-headless numpy"),
        E("Packet sniffer (SYN, UDP, port scan)", sniffer.state["running"], f"{sniffer.state['packets']} packets seen" if sniffer.state["running"] else (sniffer.state["error"] or "Start as administrator with SNIFF=1")),
        E("Anomaly detection (Isolation Forest)", _has("sklearn") and fw["anomaly"]["trained"], "Learned normal traffic" if fw["anomaly"]["trained"] else f"Learning normal traffic ({fw['anomaly']['samples']}/60 samples)" if _has("sklearn") else "pip install scikit-learn"),
        E("Telegram alerts", a["telegram"], "Active" if a["telegram"] else "Set TG_TOKEN and TG_CHAT_ID"),
        E("Email alerts", a["email"], "Active" if a["email"] else "Set SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_TO"),
    ])


@app.post("/api/alerts/test")
def alerts_test():
    return jsonify(result=" | ".join(alerts.send_now("Sentinel test alert: your notifications are working.")))


@app.get("/api/report.pdf")
def report_pdf():
    try:
        from report import build_pdf
    except ImportError:
        return jsonify(error="PDF reports need: pip install reportlab"), 501
    pdf = build_pdf(list(events), stats().get_json(), firewall.status(), engines().get_json())
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=sentinel_report.pdf"})


# ---- Gmail connection ----
@app.get("/api/integrations")
def integrations():
    return jsonify(gmail=gmail.status(), whatsapp={"configured": bool(WA_ACCESS_TOKEN), "webhook": request.host_url + "webhook/whatsapp"})


@app.get("/gmail/connect")
def gmail_connect():
    try:
        return redirect(gmail.auth_url())
    except Exception as exc:
        return f"Cannot start Gmail login: {exc}. Check that credentials.json exists and libraries are installed.", 400


@app.get("/gmail/callback")
def gmail_callback():
    try:
        gmail.finish_auth(request.url)
        gmail.start_polling(lambda r, s: log_event(r, s))
        gmail.scan_inbox(lambda r, s: log_event(r, s))
    except Exception as exc:
        return f"Gmail login failed: {exc}", 400
    return redirect("/#integrations")


@app.post("/api/gmail/scan")
def gmail_scan():
    gmail.scan_inbox(lambda r, s: log_event(r, s))
    return jsonify(gmail.status())


@app.post("/api/gmail/disconnect")
def gmail_disconnect():
    gmail.disconnect()
    return jsonify(ok=True)


# ---- WhatsApp Business Cloud API webhook (Meta) ----


@app.get("/webhook/whatsapp")
def wa_verify():
    if request.args.get("hub.verify_token") == WA_VERIFY_TOKEN:
        return request.args.get("hub.challenge", ""), 200
    return "Forbidden", 403


@app.post("/webhook/whatsapp")
def wa_receive():
    import re
    body = request.get_json(silent=True) or {}
    headers = {"Authorization": f"Bearer {WA_ACCESS_TOKEN}"}
    for entry in body.get("entry", []):
        for change in entry.get("changes", []):
            for msg in change.get("value", {}).get("messages", []):
                for url in re.findall(r"https?://\S+", msg.get("text", {}).get("body", "")):
                    log_event(analyze_url(url), "whatsapp")
                media = msg.get(msg.get("type", ""), {})
                if isinstance(media, dict) and media.get("id") and msg.get("type") in ("document", "image", "video", "audio"):
                    try:
                        meta = requests.get(f"https://graph.facebook.com/v19.0/{media['id']}", headers=headers, timeout=15).json()
                        data = requests.get(meta["url"], headers=headers, timeout=30).content
                        log_event(scan_bytes(media.get("filename") or f"{media['id']}", data), "whatsapp")
                    except Exception as exc:
                        log_event({"type": "file", "target": "WhatsApp media", "verdict": "suspicious", "score": 0,
                                   "reasons": [{"points": 0, "text": f"Could not download media: {exc}"}]}, "whatsapp")
    return "OK", 200


if __name__ == "__main__":
    if os.getenv("SNIFF") == "1":
        sniffer.start(firewall)
    if os.path.exists(gmail.TOKEN):
        gmail.start_polling(lambda r, s: log_event(r, s))
    app.run(host="127.0.0.1", port=5000, debug=False)
