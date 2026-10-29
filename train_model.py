"""Train the phishing URL model.  Usage: python train_model.py dataset.csv
CSV needs a URL column and a label column. Works with the Kaggle 'Phishing Site URLs' file (labels good/bad)
and similar sets (phishing/legitimate, 1/0). Writes model.pkl and metrics.json (shown on the dashboard)."""
import csv
import json
import sys

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from scanner.features import extract

BAD = {"bad", "phishing", "malicious", "1", "phish", "yes", "true", "malware", "defacement"}
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8", errors="ignore")))
ucol = next(k for k in rows[0] if k.lower() in ("url", "urls", "link"))
lcol = next(k for k in rows[0] if k.lower() in ("label", "class", "type", "status", "result"))
X, y = [], []
for r in rows:
    try:
        X.append(extract(r[ucol])); y.append(int(r[lcol].strip().lower() in BAD))
    except Exception:
        continue
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42).fit(Xtr, ytr)
pred = clf.predict(Xte)
m = {"samples": len(X), "accuracy": round(accuracy_score(yte, pred), 4), "precision": round(precision_score(yte, pred), 4),
     "recall": round(recall_score(yte, pred), 4), "f1": round(f1_score(yte, pred), 4),
     "confusion_matrix": confusion_matrix(yte, pred).tolist()}
joblib.dump(clf, "model.pkl")
json.dump(m, open("metrics.json", "w"), indent=2)
print(json.dumps(m, indent=2))
