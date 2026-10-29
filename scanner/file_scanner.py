"""Static file analysis: magic bytes, extension tricks, entropy, dangerous strings."""
import hashlib
import io
import math
import os
import zipfile

MAGIC = [
    (b"MZ", "exe"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"\xd0\xcf\x11\xe0", "ole"),
    (b"\x7fELF", "elf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
    (b"Rar!", "rar"), (b"#!", "script"),
]
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
                 "ps1", "jar", "msi", "hta", "lnk", "dll", "apk", "iso", "img"}
STRINGS = {
    b"powershell": 18, b"cmd.exe": 15, b"wscript.shell": 20, b"autoopen": 18, b"auto_open": 18,
    b"document_open": 18, b"/javascript": 15, b"/openaction": 18, b"/launch": 20, b"eval(": 10,
    b"frombase64string": 18, b"urldownloadtofile": 22, b"invoke-expression": 20,
    b"certutil": 15, b"bitsadmin": 15, b"mimikatz": 40,
}


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def scan_bytes(name, data):
    name = os.path.basename(name or "unknown")
    parts = name.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    reasons, score = [], 0

    def hit(points, text):
        nonlocal score
        score += points
        reasons.append({"points": points, "text": text})

    real = next((t for sig, t in MAGIC if data.startswith(sig)), "unknown")
    if real in ("exe", "elf"):
        hit(25, "File contents are an executable program")
    if ext in DANGEROUS_EXT:
        hit(30, f"'.{ext}' files can run code on your device")
        if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "jpg", "png", "txt", "xls", "xlsx"}:
            hit(30, f"Double extension '.{parts[-2]}.{ext}' disguises the real file type")
    if ext in {"jpg", "jpeg", "png", "gif", "pdf", "txt"} and real in {"exe", "elf", "script", "ole"}:
        hit(40, f"Extension says '.{ext}' but contents are '{real}' (disguised file)")
    if ext in {"docm", "xlsm", "pptm"}:
        hit(15, "Macro-enabled Office document")
    elif ext in {"doc", "xls", "ppt"} and real == "ole":
        hit(10, "Legacy Office format can contain macros")

    low = data[:2_000_000].lower()
    matched = [(s, p) for s, p in STRINGS.items() if s in low]
    if matched:
        hit(min(45, sum(p for _, p in matched)),
            "Suspicious content: " + ", ".join(s.decode() for s, _ in matched[:5]))

    if real == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = [n.lower() for n in z.namelist()]
                if any(n.endswith("vbaproject.bin") for n in names):
                    hit(30, "Archive contains a VBA macro project")
                inner = [n for n in names if n.rsplit(".", 1)[-1] in DANGEROUS_EXT]
                if inner:
                    hit(30, "Archive contains executable files: " + ", ".join(inner[:3]))
                if any(i.flag_bits & 1 for i in z.infolist()):
                    hit(15, "Password-protected archive (evades scanners)")
        except zipfile.BadZipFile:
            hit(10, "Corrupted archive")

    ent = _entropy(data[:500_000])
    if ent > 7.4 and real in ("exe", "unknown", "elf") and len(data) > 2000:
        hit(15, f"High entropy ({ent:.1f}/8): packed or encrypted content")

    from scanner import reputation
    for pts, txt in reputation.check_file(hashlib.sha256(data).hexdigest()):
        score = max(score, pts)
        reasons.append({"points": pts, "text": txt})
    score = min(score, 100)
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 25 else "safe"
    if not reasons:
        reasons.append({"points": 0, "text": "No suspicious traits found"})
    return {"type": "file", "target": name, "size": len(data), "detected_type": real,
            "sha256": hashlib.sha256(data).hexdigest(), "score": score,
            "verdict": verdict, "reasons": reasons}
