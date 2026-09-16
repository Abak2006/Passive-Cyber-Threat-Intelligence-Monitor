"""
Model Training Pipeline for NTRO Threat Detectors.
Trains and evaluates supervised classifiers and anomaly detectors without train/test leakage.
Saves serialized models under models/ directory using joblib.
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

from app.features.dns_features import DNSFeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_pipeline")

MODELS_DIR = Path("models")
DATA_DIR = Path("data/synthetic_train")


def train_ddos_model(data_path: Path, models_dir: Path) -> Dict[str, Any]:
    logger.info("Training DDoS Detection Model (Random Forest)...")
    df = pd.read_csv(data_path)
    feature_cols = [
        "packets_per_sec", "bytes_per_sec", "syn_count",
        "ack_count", "syn_ack_ratio", "mean_packet_size"
    ]
    X = df[feature_cols].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    models_dir.mkdir(parents=True, exist_ok=True)
    out_path = models_dir / "ddos_detector.joblib"
    joblib.dump(clf, out_path)
    logger.info(f"[+] Saved DDoS model to {out_path}")

    print("\n--- DDoS Detector Metrics ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "cm": cm.tolist()}


def train_dga_model(data_path: Path, models_dir: Path) -> Dict[str, Any]:
    logger.info("Training DGA Domain Classifier (Random Forest)...")
    df = pd.read_csv(data_path)

    features = []
    labels = []
    for _, row in df.iterrows():
        dom = str(row["domain"])
        lex = DNSFeatureExtractor.extract_lexical_features(dom)
        features.append([
            lex["length"],
            lex["entropy"],
            lex["digit_ratio"],
            lex["vowel_ratio"],
            lex["consonant_ratio"],
            lex["unique_char_ratio"],
            lex["max_consonant_cluster"]
        ])
        labels.append(int(row["label"]))

    X = np.array(features)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=120, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    models_dir.mkdir(parents=True, exist_ok=True)
    out_path = models_dir / "dga_detector.joblib"
    joblib.dump(clf, out_path)
    logger.info(f"[+] Saved DGA model to {out_path}")

    print("\n--- DGA Classifier Metrics ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "cm": cm.tolist()}


def train_encrypted_model(data_path: Path, models_dir: Path) -> Dict[str, Any]:
    logger.info("Training Encrypted Anomaly Detector (Random Forest Classifier)...")
    df = pd.read_csv(data_path)
    feature_cols = [
        "mean_length", "length_variance", "outbound_inbound_ratio",
        "periodicity", "suspicious_ja3", "has_sni"
    ]
    X = df[feature_cols].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    models_dir.mkdir(parents=True, exist_ok=True)
    out_path = models_dir / "encrypted_anomaly.joblib"
    joblib.dump(clf, out_path)
    logger.info(f"[+] Saved Encrypted Anomaly model to {out_path}")

    print("\n--- Encrypted Anomaly Metrics ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "cm": cm.tolist()}


def train_exfil_model(data_path: Path, models_dir: Path) -> Dict[str, Any]:
    logger.info("Training Exfiltration Detector (Isolation Forest Anomaly Model)...")
    df = pd.read_csv(data_path)
    feature_cols = ["forward_bytes", "backward_bytes", "ratio", "byte_rate", "duration"]
    X = df[feature_cols].values
    y = df["label"].values

    # Train Isolation Forest on predominantly normal traffic
    benign_X = X[y == 0]
    iso = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
    iso.fit(benign_X)

    # In IsolationForest: -1 is anomaly, 1 is normal
    preds = iso.predict(X)
    y_pred = np.where(preds == -1, 1, 0)

    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    cm = confusion_matrix(y, y_pred)

    models_dir.mkdir(parents=True, exist_ok=True)
    out_path = models_dir / "exfil_detector.joblib"
    joblib.dump(iso, out_path)
    logger.info(f"[+] Saved Exfiltration Anomaly model to {out_path}")

    print("\n--- Exfiltration Anomaly Metrics ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "cm": cm.tolist()}


def main():
    parser = argparse.ArgumentParser(description="Train NTRO Cyber Threat Detectors")
    parser.add_argument(
        "--detector",
        choices=["ddos", "dga", "encrypted", "exfil", "all"],
        default="all",
        help="Specify which detector model to train"
    )
    parser.add_argument("--data-dir", type=str, default=str(DATA_DIR), help="Path to training data directory")
    parser.add_argument("--models-dir", type=str, default=str(MODELS_DIR), help="Path to models output directory")

    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    models_dir = Path(args.models_dir)

    if not (data_dir / "dga_train.csv").exists():
        print(f"[-] Training datasets not found at {data_dir}. Generating synthetic datasets now...")
        from training.generate_synthetic import generate_training_csvs
        generate_training_csvs(data_dir)

    if args.detector in ("ddos", "all"):
        train_ddos_model(data_dir / "ddos_train.csv", models_dir)
    if args.detector in ("dga", "all"):
        train_dga_model(data_dir / "dga_train.csv", models_dir)
    if args.detector in ("encrypted", "all"):
        train_encrypted_model(data_dir / "encrypted_train.csv", models_dir)
    if args.detector in ("exfil", "all"):
        train_exfil_model(data_dir / "exfil_train.csv", models_dir)

    print("\n[+] All requested models trained and saved to", models_dir)


if __name__ == "__main__":
    main()
