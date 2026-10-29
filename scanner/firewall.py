"""Rate-based DDoS detector with automatic, time-limited blocking.
Set ENFORCE = True on Linux (run as root) to also add real nftables rules."""
import subprocess
import threading
import time
from scanner.anomaly import AnomalyDetector
from scanner import sniffer
from collections import defaultdict, deque

ENFORCE = False          # True -> also call nftables
WINDOW_SEC = 10          # sliding window
MAX_REQ_PER_IP = 80      # requests per window per IP before blocking
GLOBAL_MAX = 600         # total requests per window (distributed attack)
BLOCK_SECONDS = 300      # auto-unblock after 5 minutes
WHITELIST = set()


class Firewall:
    def __init__(self, on_event=None):
        self.hits = defaultdict(deque)
        self.blocked = {}
        self.timeline = deque(maxlen=60)
        self.total_blocked = 0
        self.on_event = on_event or (lambda e: None)
        self.lock = threading.Lock()
        self.anomaly = AnomalyDetector()
        self._n = 0
        self._bucket = 0
        threading.Thread(target=self._tick, daemon=True).start()

    def _tick(self):
        while True:
            time.sleep(1)
            with self.lock:
                self.timeline.append(self._bucket)
                self._bucket = 0
                now = time.time()
                for ip in [i for i, b in self.blocked.items() if b["until"] <= now]:
                    self._unblock(ip)
                self._n += 1
                if self._n % 5 == 0:
                    counts = {ip: sum(t > now - 5 for t in q) for ip, q in self.hits.items() if ip not in self.blocked}
                    for ip in self.anomaly.observe(counts):
                        self._block(ip, "Anomalous traffic pattern (Isolation Forest)")

    def record(self, ip):
        """Call for every incoming request. Returns False if the IP is blocked."""
        if ip in WHITELIST:
            return True
        now = time.time()
        with self.lock:
            if ip in self.blocked:
                return False
            self._bucket += 1
            q = self.hits[ip]
            q.append(now)
            while q and q[0] < now - WINDOW_SEC:
                q.popleft()
            if len(q) > MAX_REQ_PER_IP:
                self._block(ip, f"{len(q)} requests in {WINDOW_SEC}s (limit {MAX_REQ_PER_IP})")
                return False
            total = sum(len(d) for d in self.hits.values())
            if total > GLOBAL_MAX and len(self.hits) > 20:
                top = max(self.hits, key=lambda i: len(self.hits[i]))
                self._block(top, f"Distributed flood: {len(self.hits)} sources, {total} requests")
        return True

    def flag(self, ip, reason):
        """Block an IP found by another detector (packet sniffer)."""
        with self.lock:
            if ip not in WHITELIST and ip not in self.blocked:
                self._block(ip, reason)

    def _block(self, ip, reason):
        self.blocked[ip] = {"until": time.time() + BLOCK_SECONDS, "reason": reason}
        self.total_blocked += 1
        if ENFORCE:
            subprocess.run(["nft", "add", "element", "inet", "filter", "blocklist",
                            f"{{ {ip} timeout {BLOCK_SECONDS}s }}"], check=False)
        self.on_event({"type": "firewall", "target": ip, "verdict": "blocked", "score": 100,
                       "reasons": [{"points": 0, "text": reason}]})

    def _unblock(self, ip):
        self.blocked.pop(ip, None)
        self.hits.pop(ip, None)
        if ENFORCE:
            subprocess.run(["nft", "delete", "element", "inet", "filter", "blocklist",
                            f"{{ {ip} }}"], check=False)

    def unblock(self, ip):
        with self.lock:
            self._unblock(ip)

    def status(self):
        now = time.time()
        with self.lock:
            return {"blocked": [{"ip": ip, "reason": b["reason"], "seconds_left": int(b["until"] - now)}
                                for ip, b in self.blocked.items()],
                    "timeline": list(self.timeline), "total_blocked": self.total_blocked,
                    "limit": MAX_REQ_PER_IP, "window": WINDOW_SEC, "enforce": ENFORCE,
                    "anomaly": {"trained": self.anomaly.model is not None, "samples": len(self.anomaly.hist)}, "sniffer": sniffer.state}

    def simulate_attack(self, sources=1, per_source=120):
        """Lab demo: pushes fake traffic through the detector (no real packets)."""
        for s in range(sources):
            ip = f"203.0.113.{10 + s}"
            for _ in range(per_source):
                self.record(ip)
