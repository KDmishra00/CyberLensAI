"""Model loading and batch inference.

The pipeline saved by train_model.py is loaded once at import time. If the
model file is missing, HAS_MODEL is False and the app shows a friendly
banner instead of a stack trace.
"""
from __future__ import annotations

import json

import joblib
import pandas as pd

import config


class AnalysisError(RuntimeError):
    """Inference failed; the message is shown to the user, not swallowed."""


def _load():
    try:
        model = joblib.load(config.MODEL_PATH)
        with open(config.METRICS_PATH, encoding="utf-8") as fh:
            metrics = json.load(fh)
        return model, metrics
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, KeyError) as exc:
        raise AnalysisError(f"The model file exists but could not be loaded: {exc}") from exc


model, metrics = _load()
HAS_MODEL = model is not None

BATCH_SIZE = 20_000


def predict(df: pd.DataFrame) -> pd.DataFrame:
    """Add predicted_category, confidence and is_anomaly columns to df.

    A row predicted as an attack below config.CONFIDENCE_ANOMALY_THRESHOLD
    stays "Normal" but is counted as low-confidence, so the dashboard can
    be honest about uncertainty.
    """
    if not HAS_MODEL:
        raise AnalysisError("Model not found. Run `python train_model.py` first.")

    try:
        numeric = [c for c in config.MODEL_NUMERIC_FEATURES if c in df.columns]
        missing_numeric = [c for c in config.MODEL_NUMERIC_FEATURES if c not in df.columns]
        if missing_numeric:
            # A parse that skipped feature computation should never reach here,
            # but fill defensively rather than crashing inside sklearn.
            for col in missing_numeric:
                df[col] = 0
            numeric = config.MODEL_NUMERIC_FEATURES
        features = df[numeric + [config.TEXT_FEATURE]].copy()
        # pandas 3 StringDtype confuses some sklearn encoders; make it plain object.
        features[config.TEXT_FEATURE] = features[config.TEXT_FEATURE].fillna("").astype(object)

        categories, confidences = [], []
        for start in range(0, len(features), BATCH_SIZE):
            batch = features.iloc[start:start + BATCH_SIZE]
            proba = model.predict_proba(batch)
            best = proba.argmax(axis=1)
            categories.extend(model.classes_[best])
            confidences.extend(proba.max(axis=1))
    except AnalysisError:
        raise
    except Exception as exc:  # anything inside sklearn - surface a clear error
        raise AnalysisError(f"Model inference failed: {exc}") from exc

    out = df.copy()
    out["predicted_category"] = list(categories)
    out["confidence"] = [round(float(c), 4) for c in confidences]

    attack = out["predicted_category"] != config.NORMAL_LABEL
    low_conf = attack & (out["confidence"] < config.CONFIDENCE_ANOMALY_THRESHOLD)
    out["is_anomaly"] = attack & ~low_conf
    out.loc[low_conf, "predicted_category"] = config.NORMAL_LABEL
    out["low_confidence"] = low_conf
    return out


def reliability_warning(df: pd.DataFrame) -> str | None:
    """Warn when the data barely resembles anything the model knows."""
    empty_text = df[config.TEXT_FEATURE].fillna("").str.strip().eq("")
    all_zero = (df[[c for c in config.MODEL_NUMERIC_FEATURES
                    if c.startswith(("ip_", "has_")) ]] == 0).all(axis=1)
    if (empty_text & all_zero).mean() > 0.9:
        return ("Most rows in this file have no readable message and no usable "
                "features, so the results may be unreliable. The model only "
                "classifies the seven categories it was trained on.")
    return None
