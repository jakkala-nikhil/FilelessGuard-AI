"""Train and evaluate the Random Forest classifier.

Usage:
    python train.py                    # trains on synthetic demo data
    python train.py --csv mydata.csv   # trains on a real labelled CSV

CSV columns: name, parent_name, cmdline, cpu_percent, memory_mb,
             num_children, chain_depth, label  (0 = benign, 1 = malicious)
"""
import argparse
import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import cross_val_score, train_test_split

from src.data_gen import generate
from src.features import FEATURES, extract_features

MODEL_PATH = "models/rf_model.joblib"
METRICS_PATH = "models/metrics.json"


def build_matrix(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame([extract_features(r) for r in df.to_dict("records")])[FEATURES]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="real labelled dataset (otherwise synthetic demo data)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs("models", exist_ok=True)
    if args.csv:
        df, source = pd.read_csv(args.csv), f"real dataset: {args.csv}"
    else:
        df, source = generate(seed=args.seed), "SYNTHETIC demo data (not real-world evidence)"
    print("Data source:", source, "| samples:", len(df), "| malicious ratio:", round(df.label.mean(), 3))

    X, y = build_matrix(df), df["label"].values
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=args.seed)

    model = RandomForestClassifier(n_estimators=200, max_depth=12, class_weight="balanced",
                                   random_state=args.seed, n_jobs=-1)
    cv = cross_val_score(model, X_tr, y_tr, cv=5, scoring="recall")
    model.fit(X_tr, y_tr)

    pred = model.predict(X_te)
    tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
    m = {
        "data_source": source, "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
        "accuracy": round(accuracy_score(y_te, pred), 4),
        "precision": round(precision_score(y_te, pred), 4),
        "recall": round(recall_score(y_te, pred), 4),
        "f1": round(f1_score(y_te, pred), 4),
        "cv_recall_mean": round(float(cv.mean()), 4), "cv_recall_std": round(float(cv.std()), 4),
        "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
    }
    json.dump(m, open(METRICS_PATH, "w"), indent=2)
    joblib.dump({"model": model, "features": FEATURES}, MODEL_PATH)
    print(json.dumps(m, indent=2))

    # confusion matrix figure
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    cm = np.array([[tn, fp], [fn, tp]])
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=16,
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["Benign", "Malicious"]); ax.set_yticks([0, 1], ["Benign", "Malicious"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion matrix (held-out test set)")
    fig.tight_layout(); fig.savefig("models/confusion_matrix.png", dpi=150); plt.close(fig)

    # feature importance figure
    imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    imp.plot.barh(ax=ax, color="#2E75B6"); ax.set_title("Random Forest feature importance")
    fig.tight_layout(); fig.savefig("models/feature_importance.png", dpi=150); plt.close(fig)
    print("Saved model + figures in models/")


if __name__ == "__main__":
    main()
