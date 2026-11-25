"""Analysis engine (Random Forest) and alert system."""
import csv
import hashlib
import os
from datetime import datetime

import joblib
import pandas as pd

from src.features import extract_features, reasons

MODEL_PATH = "models/rf_model.joblib"
ALERT_FILE = "logs/alerts.csv"
ALERT_COLS = ["time", "pid", "name", "parent_name", "verdict", "probability", "indicator", "cmdline"]


class Detector:
    def __init__(self, model_path=MODEL_PATH, malicious_thr=0.80, suspicious_thr=0.50):
        bundle = joblib.load(model_path)
        self.model, self.features = bundle["model"], bundle["features"]
        self.mal_thr, self.sus_thr = malicious_thr, suspicious_thr

    def score(self, records: list) -> pd.DataFrame:
        if not records:
            return pd.DataFrame()
        feats = [extract_features(r) for r in records]
        X = pd.DataFrame(feats)[self.features]
        proba = self.model.predict_proba(X)[:, 1]
        out = []
        for r, f, p in zip(records, feats, proba):
            verdict = "MALICIOUS" if p >= self.mal_thr else "SUSPICIOUS" if p >= self.sus_thr else "BENIGN"
            out.append({
                "pid": r.get("pid"), "name": r.get("name"), "parent_name": r.get("parent_name"),
                "verdict": verdict, "probability": round(float(p), 3),
                "indicator": ("; ".join(reasons(f)) or "Anomalous behaviour pattern (model score)")
                             if verdict != "BENIGN" else "Normal behaviour",
                "cpu_percent": r.get("cpu_percent"), "memory_mb": r.get("memory_mb"),
                "cmdline": (r.get("cmdline") or "")[:300],
            })
        return pd.DataFrame(out).sort_values("probability", ascending=False).reset_index(drop=True)


class AlertLog:
    """Writes each new SUSPICIOUS/MALICIOUS finding once to logs/alerts.csv."""

    def __init__(self, path=ALERT_FILE):
        self.path, self.seen = path, set()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(ALERT_COLS)

    def add(self, scored: pd.DataFrame) -> pd.DataFrame:
        if scored.empty:
            return scored
        new_rows = []
        for r in scored[scored.verdict != "BENIGN"].to_dict("records"):
            key = (r["pid"], r["name"], hashlib.md5(r["cmdline"].encode()).hexdigest())
            if key in self.seen:
                continue
            self.seen.add(key)
            r["time"] = datetime.now().strftime("%H:%M:%S")
            new_rows.append(r)
        if new_rows:
            with open(self.path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=ALERT_COLS, extrasaction="ignore")
                w.writerows(new_rows)
        return pd.DataFrame(new_rows)

    def history(self, n=50) -> pd.DataFrame:
        try:
            return pd.read_csv(self.path).tail(n).iloc[::-1].reset_index(drop=True)
        except Exception:
            return pd.DataFrame(columns=ALERT_COLS)
