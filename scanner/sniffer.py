"""Packet-level detection with Scapy: SYN flood, UDP flood, port scan.
Needs administrator/root (Windows: install Npcap). Enable with environment variable SNIFF=1."""
import threading
import time
from collections import defaultdict

state = {"running": False, "packets": 0, "error": None}


def start(fw):
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError:
        state["error"] = "Install scapy: pip install scapy"
        return
    syn, udp, ports, t0 = defaultdict(int), defaultdict(int), defaultdict(set), [time.time()]

    def handle(p):
        if IP not in p:
            return
        state["packets"] += 1
        src = p[IP].src
        if TCP in p:
            f = int(p[TCP].flags)
            if f & 0x02 and not f & 0x10:
                syn[src] += 1
            ports[src].add(p[TCP].dport)
        elif UDP in p:
            udp[src] += 1
        if time.time() - t0[0] >= 5:
            for ip, n in syn.items():
                n > 200 and fw.flag(ip, f"SYN flood: {n} connection attempts in 5s")
            for ip, n in udp.items():
                n > 400 and fw.flag(ip, f"UDP flood: {n} packets in 5s")
            for ip, s in ports.items():
                len(s) > 40 and fw.flag(ip, f"Port scan: {len(s)} different ports probed")
            syn.clear(); udp.clear(); ports.clear(); t0[0] = time.time()

    def run():
        try:
            state["running"] = True
            sniff(prn=handle, store=False)
        except Exception as exc:
            state.update(running=False, error=str(exc)[:150])
    threading.Thread(target=run, daemon=True).start()
