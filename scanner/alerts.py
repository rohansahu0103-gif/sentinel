"""Telegram and email alerts. Env: TG_TOKEN, TG_CHAT_ID | SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_TO."""
import os
import smtplib
import threading
import time
from collections import deque
from email.message import EmailMessage

import requests

_recent = deque(maxlen=10)


def configured():
    return {"telegram": bool(os.getenv("TG_TOKEN") and os.getenv("TG_CHAT_ID")),
            "email": bool(os.getenv("SMTP_HOST") and os.getenv("ALERT_TO"))}


def send_now(text):
    res = []
    if configured()["telegram"]:
        try:
            r = requests.post(f"https://api.telegram.org/bot{os.getenv('TG_TOKEN')}/sendMessage",
                              json={"chat_id": os.getenv("TG_CHAT_ID"), "text": text}, timeout=10)
            res.append("Telegram sent" if r.ok else f"Telegram error: {r.text[:80]}")
        except Exception as exc:
            res.append(f"Telegram error: {exc}")
    if configured()["email"]:
        try:
            m = EmailMessage()
            m["Subject"], m["From"], m["To"] = "Sentinel security alert", os.getenv("SMTP_USER", "sentinel@localhost"), os.getenv("ALERT_TO")
            m.set_content(text)
            with smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT", "587")), timeout=10) as s:
                s.starttls()
                if os.getenv("SMTP_USER"):
                    s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS", ""))
                s.send_message(m)
            res.append("Email sent")
        except Exception as exc:
            res.append(f"Email error: {exc}")
    return res or ["No alert channel configured"]


def send(text):
    """Background send, max 10 alerts per minute to avoid spam during floods."""
    now = time.time()
    if len(_recent) == 10 and now - _recent[0] < 60:
        return
    _recent.append(now)
    if any(configured().values()):
        threading.Thread(target=send_now, args=(text,), daemon=True).start()
