"""
Machine Learning Pipeline
─────────────────────────
1. Feature engineering from raw login_logs (rolling windows)
2. Model training  – Random Forest Classifier + Isolation Forest
3. Inference       – called on every login attempt at runtime
4. Auto-export     – joblib artefacts saved to disk
"""
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.models import LoginLog, LoginStatus, AttackType, MLAnomaly
from backend.models.database import AsyncSessionLocal
from config import settings

log = logging.getLogger(__name__)

MODEL_PATH  = Path(settings.MODEL_PATH)
SCALER_PATH = Path(settings.SCALER_PATH)

# Ensure directories exist
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)


# ── Feature Engineering ───────────────────────────────────────────────────────

WINDOW_SECONDS = [60, 300, 900]  # 1 min, 5 min, 15 min rolling windows


def engineer_features(df: pd.DataFrame, window_secs: int = 300) -> pd.DataFrame:
    """
    Aggregates raw log rows into per-IP feature vectors using a rolling window.

    Input columns expected: timestamp, ip_address, attempted_username, status

    Output features per IP:
        failed_attempts_count    – total failures in window
        unique_users_targeted    – distinct usernames tried
        request_frequency        – requests per second
        success_ratio            – fraction of successes
        unique_ip_count_for_user – distinct IPs targeting same username
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["is_failure"] = (df["status"] == LoginStatus.FAILURE.value).astype(int)
    df["is_success"] = (df["status"] == LoginStatus.SUCCESS.value).astype(int)

    cutoff = df["timestamp"].max() - timedelta(seconds=window_secs)
    window_df = df[df["timestamp"] >= cutoff]

    # Per-IP aggregation
    ip_features = (
        window_df.groupby("ip_address")
        .agg(
            failed_attempts_count=("is_failure", "sum"),
            unique_users_targeted=("attempted_username", "nunique"),
            total_requests=("ip_address", "count"),
            success_count=("is_success", "sum"),
        )
        .reset_index()
    )

    # Time span of activity for frequency calculation
    ip_time = (
        window_df.groupby("ip_address")["timestamp"]
        .agg(["min", "max"])
        .reset_index()
    )
    ip_time["duration_secs"] = (
        ip_time["max"] - ip_time["min"]
    ).dt.total_seconds().clip(lower=1)
    ip_features = ip_features.merge(ip_time[["ip_address", "duration_secs"]], on="ip_address")
    ip_features["request_frequency"] = ip_features["total_requests"] / ip_features["duration_secs"]
    ip_features["success_ratio"] = ip_features["success_count"] / ip_features["total_requests"].clip(lower=1)

    # How many distinct IPs target the same username (helps detect stuffing)
    ip_user_spread = (
        window_df.groupby("attempted_username")["ip_address"]
        .nunique()
        .reset_index()
        .rename(columns={"ip_address": "unique_ip_count_for_user"})
    )
    # Assign max unique_ip_count across all usernames tried by this IP
    window_df = window_df.merge(ip_user_spread, on="attempted_username", how="left")
    ip_max_spread = (
        window_df.groupby("ip_address")["unique_ip_count_for_user"]
        .max()
        .reset_index()
    )
    ip_features = ip_features.merge(ip_max_spread, on="ip_address", how="left")
    ip_features["unique_ip_count_for_user"] = ip_features["unique_ip_count_for_user"].fillna(1)

    return ip_features


FEATURE_COLS = [
    "failed_attempts_count",
    "unique_users_targeted",
    "request_frequency",
    "success_ratio",
    "unique_ip_count_for_user",
]


# ── Synthetic Training Data Generator (bootstrap when DB is empty) ─────────────

def generate_synthetic_training_data(n_normal=500, n_attack=200) -> pd.DataFrame:
    """
    Generates labelled training rows for bootstrapping the model.
    Label: 0 = normal, 1 = attack
    """
    rng = np.random.default_rng(42)

    normal = pd.DataFrame({
        "failed_attempts_count":   rng.integers(0, 3,  n_normal),
        "unique_users_targeted":   rng.integers(1, 2,  n_normal),
        "request_frequency":       rng.uniform(0.01, 0.5, n_normal),
        "success_ratio":           rng.uniform(0.5, 1.0,  n_normal),
        "unique_ip_count_for_user":rng.integers(1, 3,  n_normal),
        "label": 0,
    })

    brute_force = pd.DataFrame({
        "failed_attempts_count":   rng.integers(10, 200, n_attack // 3),
        "unique_users_targeted":   rng.integers(1,   2,  n_attack // 3),
        "request_frequency":       rng.uniform(2.0, 20.0, n_attack // 3),
        "success_ratio":           rng.uniform(0.0,  0.1, n_attack // 3),
        "unique_ip_count_for_user":rng.integers(1,   2,  n_attack // 3),
        "label": 1,
    })

    spray = pd.DataFrame({
        "failed_attempts_count":   rng.integers(5, 50, n_attack // 3),
        "unique_users_targeted":   rng.integers(10, 100, n_attack // 3),
        "request_frequency":       rng.uniform(1.0, 10.0, n_attack // 3),
        "success_ratio":           rng.uniform(0.0, 0.05, n_attack // 3),
        "unique_ip_count_for_user":rng.integers(1,   3,  n_attack // 3),
        "label": 1,
    })

    stuffing = pd.DataFrame({
        "failed_attempts_count":   rng.integers(3, 30, n_attack // 3),
        "unique_users_targeted":   rng.integers(5, 50, n_attack // 3),
        "request_frequency":       rng.uniform(0.5, 5.0, n_attack // 3),
        "success_ratio":           rng.uniform(0.0, 0.1, n_attack // 3),
        "unique_ip_count_for_user":rng.integers(10, 100, n_attack // 3),
        "label": 1,
    })

    return pd.concat([normal, brute_force, spray, stuffing], ignore_index=True)


# ── Training ──────────────────────────────────────────────────────────────────

def train_model(df: Optional[pd.DataFrame] = None) -> dict:
    """
    Trains a Random Forest classifier + fits an Isolation Forest for unsupervised
    anomaly detection. Saves both models and the scaler to disk.

    If df is None, synthetic data is used (good for first run).

    Returns a dict with evaluation metrics.
    """
    if df is None or len(df) < 50:
        log.info("Using synthetic training data (insufficient real data).")
        df = generate_synthetic_training_data()

    X = df[FEATURE_COLS].values
    y = df["label"].values

    # ── Scale features ───────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Supervised: Random Forest ─────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    # ── Unsupervised: Isolation Forest (detects novel anomalies) ──────────────
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled)

    # ── Persist ───────────────────────────────────────────────────────────────
    joblib.dump({"rf": rf, "iso": iso}, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    log.info("Models saved to %s | Scaler saved to %s", MODEL_PATH, SCALER_PATH)

    metrics = {
        "accuracy":  report["accuracy"],
        "precision": report.get("1", {}).get("precision", 0),
        "recall":    report.get("1", {}).get("recall", 0),
        "f1":        report.get("1", {}).get("f1-score", 0),
        "training_rows": len(df),
    }
    log.info("Training complete: %s", metrics)
    return metrics


# ── Inference ─────────────────────────────────────────────────────────────────

class ThreatDetector:
    """
    Singleton wrapper around the loaded models.
    Call `predict(features_dict)` at runtime.
    """
    _instance = None

    def __init__(self):
        self._models = None
        self._scaler = None
        self._load()

    @classmethod
    def get(cls) -> "ThreatDetector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load(self):
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            self._models = joblib.load(MODEL_PATH)
            self._scaler = joblib.load(SCALER_PATH)
            log.info("ML models loaded from disk.")
        else:
            log.warning("No trained model found. Run /api/admin/ml/train first.")

    def reload(self):
        self._load()

    def predict(self, features: dict) -> tuple[bool, float]:
        """
        Returns (is_threat: bool, anomaly_score: float 0–1).
        Falls back to rule-based heuristic if models not loaded.
        """
        if self._models is None or self._scaler is None:
            # Simple heuristic fallback
            score = min(features.get("failed_attempts_count", 0) / 20.0, 1.0)
            return score >= settings.ANOMALY_THRESHOLD, score

        vec = np.array([[features.get(c, 0) for c in FEATURE_COLS]])
        vec_scaled = self._scaler.transform(vec)

        # RF probability of class 1 (attack)
        rf_score = float(self._models["rf"].predict_proba(vec_scaled)[0][1])

        # Isolation Forest score: -1 = anomaly, 1 = normal → map to 0–1
        iso_raw   = float(self._models["iso"].score_samples(vec_scaled)[0])
        iso_score = 1.0 - (iso_raw - (-0.5)) / 1.0   # rough normalisation
        iso_score = max(0.0, min(1.0, iso_score))

        # Ensemble: weighted average
        combined  = 0.7 * rf_score + 0.3 * iso_score
        is_threat = combined >= settings.ANOMALY_THRESHOLD
        return is_threat, round(combined, 4)


async def run_inference_for_ip(db: AsyncSession, ip: str) -> tuple[bool, float]:
    """
    Builds feature vector from recent logs for `ip`, runs inference,
    stores an MLAnomaly record if flagged, and returns (is_threat, score).
    """
    # Fetch last 300 s of logs
    cutoff = datetime.utcnow() - timedelta(seconds=300)
    from sqlalchemy import select
    from backend.models.models import LoginLog as LL
    result = await db.execute(
        select(LL).where(LL.timestamp >= cutoff)
    )
    rows = result.scalars().all()

    if not rows:
        return False, 0.0

    data = pd.DataFrame([{
        "timestamp":          r.timestamp,
        "ip_address":         r.ip_address,
        "attempted_username": r.attempted_username,
        "status":             r.status.value,
    } for r in rows])

    features_df = engineer_features(data, window_secs=300)
    ip_row = features_df[features_df["ip_address"] == ip]

    if ip_row.empty:
        return False, 0.0

    features = ip_row[FEATURE_COLS].iloc[0].to_dict()
    detector = ThreatDetector.get()
    is_threat, score = detector.predict(features)

    if is_threat:
        anomaly = MLAnomaly(
            ip_address=ip,
            ml_score=score,
            features=json.dumps(features),
            action_taken="flagged",
        )
        db.add(anomaly)
        await db.commit()

    return is_threat, score
