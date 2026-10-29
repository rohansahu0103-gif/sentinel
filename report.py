"""Professional PDF security report for Sentinel."""
import io
import time
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BRAND = colors.HexColor("#0f4c5c")
LIGHT = colors.HexColor("#eef1f4")
VC = {"safe": "#1f7a4d", "suspicious": "#a86400", "malicious": "#b42318", "blocked": "#7a1f16", "invalid": "#5b6b7a"}
TYPE = {"url": "Link", "file": "File", "email": "Email", "firewall": "Network"}
ss = getSampleStyleSheet()
BODY = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13.5)
CELL = ParagraphStyle("c", parent=BODY, fontSize=8.8, leading=12)
H1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=15, textColor=BRAND, spaceBefore=14, spaceAfter=6, keepWithNext=1)
H2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11.5, textColor=BRAND, spaceBefore=8, spaceAfter=4, keepWithNext=1)
P = lambda t, st=BODY: Paragraph(escape(str(t)), st)
PX = lambda t, st=BODY: Paragraph(t, st)
B = lambda t: PX(f"<b>{escape(t)}</b>", CELL)

ACTIONS = {
    ("url", "malicious"): "Do not open this link. Delete the message that contained it and warn the sender or group. If you already opened it, follow Section 7.",
    ("url", "suspicious"): "Avoid opening it. Type the official website address yourself, or confirm with the sender through another channel (call or meet).",
    ("url", "invalid"): "The address is broken or does not exist. Ask the sender for the correct link instead of guessing.",
    ("file", "malicious"): "Do not open or run this file. Delete it, empty the recycle bin and run a full antivirus scan. Report the sender.",
    ("file", "suspicious"): "Do not open it yet. Confirm with the sender through another channel and scan with updated antivirus. If you must open it, use a virtual machine.",
    ("email", "malicious"): "Treat the email as forged. Do not reply, click links or open attachments. Mark it as phishing and delete it.",
    ("email", "suspicious"): "Verify the sender through another channel before acting. Check the real sender address, not just the display name.",
    ("firewall", "blocked"): "The address was blocked automatically. Keep it blocked if unknown, check server logs and load, and for large attacks contact your host or use a CDN with DDoS protection.",
}
PRECAUTIONS = [
    ("Links and phishing", ["Check the full address before clicking. Look-alike names (paypa1.com, sbi-secure-login.xyz) are the most common trick.",
        "Be careful with shortened links (bit.ly and similar). Expand them with a preview tool first.",
        "Banks, UPI apps and delivery companies never ask for OTP, PIN, CVV or passwords through a link.",
        "Urgent threats such as 'account will be blocked in 24 hours' are a pressure tactic. Pause and verify.",
        "Type the official website or use the official app instead of following links from messages."]),
    ("Files and attachments", ["Never open .exe, .scr, .bat, .js, .vbs, .lnk, .iso or double-extension files such as invoice.pdf.exe.",
        "Do not enable macros in Word or Excel files from unknown senders.",
        "Be careful with password-protected zip files from strangers; they are used to bypass scanners.",
        "Keep antivirus and the operating system updated and download software only from official sites."]),
    ("Email and WhatsApp", ["Check the real sender address and the Reply-To address. A mismatch is a strong warning sign.",
        "Do not trust messages only because they come from a known contact; accounts get hacked. Confirm by phone.",
        "Turn on two-step verification for Gmail and WhatsApp.",
        "Do not forward suspicious messages or files. Report and delete them."]),
    ("Accounts and passwords", ["Use a different strong password for each account and keep them in a password manager.",
        "Enable two-factor authentication everywhere it is offered, preferably with an authenticator app.",
        "Change the password immediately if you suspect it was exposed."]),
    ("Network and DDoS protection", ["Keep the firewall rule limits and the IP whitelist reviewed, and never whitelist unknown addresses.",
        "Put public servers behind a CDN or DDoS protection service; a local firewall cannot stop attacks that fill your internet bandwidth.",
        "Close unused ports, update server software and watch traffic graphs for sudden spikes.",
        "Keep logs and this report for incident review. Test attack simulations only on systems you own."]),
]
CLICKED = ["Disconnect from the internet if you opened a file that may be malware.", "Do not enter any more information on the page. Close it.",
           "Change the password of the affected account from a different, clean device, and turn on two-step verification.",
           "If you shared card, UPI or bank details, call your bank at once and block the card or account. In India you can also report at cybercrime.gov.in or call 1930.",
           "Run a full antivirus scan and remove unknown programs and browser extensions.",
           "Check the account for unknown logins, forwarding rules or sent messages and sign out of all devices.",
           "Tell people who may have received the same link or file from you."]


def _bars(counts, total):
    d = Drawing(480, len(counts) * 22 + 4)
    y = len(counts) * 22 - 18
    for k, v in counts:
        w = v / max(total, 1) * 300
        d.add(String(0, y + 4, k.capitalize(), fontSize=9, fontName="Helvetica"))
        d.add(Rect(90, y, max(w, 1), 14, fillColor=colors.HexColor(VC[k]), strokeColor=None))
        d.add(String(96 + w, y + 4, str(v), fontSize=9, fontName="Helvetica"))
        y -= 22
    return d


def _rating(d):
    s, t = d["score"], d["total"]
    if not t:
        return "No data", "#5b6b7a", "No items were checked in this period. Check links or files, or connect Gmail, to generate findings."
    lvl = ("Low risk", "#1f7a4d") if s >= 85 else ("Moderate risk", "#a86400") if s >= 60 else ("High risk", "#b42318") if s >= 40 else ("Critical risk", "#7a1f16")
    return lvl[0], lvl[1], (f"Sentinel analysed {t} items and flagged {d['threats']} as suspicious, malicious or blocked. "
                            f"The overall security score is {s} out of 100, which is rated {lvl[0].lower()}. "
                            "Review the detailed findings in Section 3 and apply the recommended actions and precautions.")


def _finding(i, e):
    col = colors.HexColor(VC.get(e["verdict"], "#5b6b7a"))
    head = PX(f'<font color="white"><b>#{i} &nbsp;{e["verdict"].upper()} &nbsp;|&nbsp; {TYPE.get(e["type"], e["type"])} &nbsp;|&nbsp; source: {escape(e["source"])} &nbsp;|&nbsp; {e["time"]}'
              f'{" &nbsp;|&nbsp; sample data" if e.get("demo") else ""}</b></font>', CELL)
    finds = "<br/>".join("&bull; " + escape(r["text"]) for r in sorted(e["reasons"], key=lambda r: -r["points"])[:7])
    action = ACTIONS.get((e["type"], e["verdict"])) or ACTIONS.get((e["type"], "suspicious"), "Review this item before trusting it.")
    rows = [[head, ""], [B("Item"), P(e["target"][:220], CELL)], [B("Risk score"), P(f"{e['score']} / 100", CELL)],
            [B("What was found"), PX(finds, CELL)], [B("Recommended action"), P(action, CELL)]]
    if e.get("sha256"):
        rows.insert(2, [B("SHA-256"), P(e["sha256"], CELL)])
    t = Table(rows, colWidths=[34 * mm, 138 * mm])
    t.setStyle(TableStyle([("SPAN", (0, 0), (1, 0)), ("BACKGROUND", (0, 0), (1, 0), col), ("BACKGROUND", (0, 1), (0, -1), LIGHT),
                           ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#c5ced6")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return KeepTogether([t, Spacer(1, 8)])


def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    st = [("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#c5ced6")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), BRAND), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 9)]
    t.setStyle(TableStyle(st))
    return t


def _footer(c, doc):
    c.saveState()
    c.setFont("Helvetica", 8)
    c.setFillColor(colors.grey)
    c.drawString(18 * mm, 10 * mm, "Sentinel Security Report - confidential, for the owner of this system")
    c.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    c.restoreState()


def build_pdf(events, d, fw, engines):
    now = time.strftime("%d %B %Y, %H:%M")
    name, col, summary = _rating(d)
    times = [e["time"] for e in events]
    S = []
    hdr = Table([[PX('<font color="white" size="22"><b>Sentinel Security Report</b></font>', ParagraphStyle("t1", parent=BODY, leading=28))],
                 [PX('<font color="#cfe3e8" size="10">Phishing, malicious file and DDoS protection summary</font>', ParagraphStyle("t2", parent=BODY, leading=14))]], colWidths=[174 * mm])
    hdr.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BRAND), ("LEFTPADDING", (0, 0), (-1, -1), 14), ("TOPPADDING", (0, 0), (0, 0), 14), ("BOTTOMPADDING", (0, 1), (0, 1), 14)]))
    S += [hdr, Spacer(1, 10), _table([[B("Report ID"), P("SNT-" + time.strftime("%Y%m%d-%H%M"), CELL), B("Generated"), P(now, CELL)],
                                      [B("Items analysed"), P(d["total"], CELL), B("Activity window"), P(f"{times[-1]} to {times[0]}" if times else "-", CELL)]],
                                     [30 * mm, 57 * mm, 30 * mm, 57 * mm], header=False)]
    S += [P("1. Executive summary", H1), PX(f'Overall rating: <font color="{col}"><b>{name}</b></font>'), Spacer(1, 4), P(summary), Spacer(1, 8),
          _table([["Security score", "Items checked", "Threats found", "IPs blocked"], [P(f"{d['score']} / 100", CELL), d["total"], d["threats"], d["blocked_ips"]]], [43 * mm] * 4)]
    order = ["safe", "suspicious", "malicious", "blocked", "invalid"]
    S += [P("2. Activity overview", H1), P("Result of every check", H2), _bars([(k, d["verdicts"].get(k, 0)) for k in order], d["total"]), Spacer(1, 6)]
    S += [_table([["Where items came from", "Count", "Type of item", "Count"]] + [
        [list(d["sources"])[i] if i < len(d["sources"]) else "", list(d["sources"].values())[i] if i < len(d["sources"]) else "",
         TYPE.get(list(d["types"])[i], list(d["types"])[i]) if i < len(d["types"]) else "", list(d["types"].values())[i] if i < len(d["types"]) else ""]
        for i in range(max(len(d["sources"]), len(d["types"]), 1))], [55 * mm, 31 * mm, 55 * mm, 31 * mm])]
    if d["top_reasons"]:
        S += [P("Most common warning signs", H2), _table([["Warning sign", "Times seen"]] + [[P(n, CELL), c] for n, c in d["top_reasons"]], [140 * mm, 32 * mm])]
    S += [P("3. Detailed findings", H1)]
    bad = sorted([e for e in events if e["verdict"] != "safe"], key=lambda e: -e["score"])[:30]
    S += [_finding(i, e) for i, e in enumerate(bad, 1)] or [P("No suspicious or malicious items were found.")]
    S += [P("4. Network protection", H1), P(f"The firewall blocks an IP address that sends more than {fw['limit']} requests within {fw['window']} seconds, "
                                            f"and blocks addresses whose traffic pattern differs from normal. Blocks so far: {fw['total_blocked']}. Currently blocked: {len(fw['blocked'])}.")]
    if fw["blocked"]:
        S += [Spacer(1, 4), _table([["IP address", "Reason", "Unblocks in"]] + [[b["ip"], P(b["reason"], CELL), f"{b['seconds_left']} s"] for b in fw["blocked"]], [38 * mm, 100 * mm, 34 * mm])]
    S += [P("5. Detection methods used", H1), _table([["Engine", "Status", "Details"]] + [[P(e["name"], CELL), "Active" if e["on"] else "Off", P(e["detail"], CELL)] for e in engines], [64 * mm, 20 * mm, 88 * mm])]
    S += [P("6. Precautions and best practices", H1)]
    for title, items in PRECAUTIONS:
        S += [KeepTogether([P(title, H2)] + [PX("&bull; " + escape(i), BODY) for i in items])]
    S += [P("7. If you already clicked a link or opened a file", H1)] + [PX(f"<b>{n}.</b> {escape(t)}") for n, t in enumerate(CLICKED, 1)]
    S += [P("8. Limitations", H1), P("Sentinel uses static analysis, reputation lookups and statistical models. It does not run files in a sandbox, so a new or heavily "
                                     "disguised threat can be missed, and some safe items can be flagged by mistake. Treat the results as a first line of defence and "
                                     "not as a replacement for antivirus software, careful judgement and verification with the sender.")]
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, title="Sentinel Security Report", leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm).build(S, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
