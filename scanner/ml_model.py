"""Loads model.pkl (made by train_model.py) and returns phishing probability 0..1."""
import json
import os

from scanner.features import extract

ROOT = os.path.join(os.path.dirname(__file__), "..")
MODEL_PATH, METRICS_PATH = os.path.join(ROOT, "model.pkl"), os.path.join(ROOT, "metrics.json")
_model = None


def predict(url):
    global _model
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        if _model is None:
            import joblib
            _model = joblib.load(MODEL_PATH)
        return float(_model.predict_proba([extract(url)])[0][1])
    except Exception:
        return None


def metrics():
    try:
        return json.load(open(METRICS_PATH))
    except Exception:
        return None
