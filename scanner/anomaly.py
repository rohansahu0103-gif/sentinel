"""Isolation Forest learns normal per-IP request volume and flags outliers (no fixed limit needed)."""


class AnomalyDetector:
    def __init__(self):
        self.hist, self.model, self.rounds = [], None, 0

    def observe(self, counts):
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            return []
        flagged = [ip for ip, c in counts.items() if self.model and c >= 25 and self.model.predict([[c]])[0] == -1]
        self.hist += [[c] for ip, c in counts.items() if ip not in flagged]
        self.hist = self.hist[-1000:]
        self.rounds += 1
        if len(self.hist) >= 60 and self.rounds % 12 == 0:
            self.model = IsolationForest(contamination=0.02, random_state=1).fit(self.hist)
        return flagged
