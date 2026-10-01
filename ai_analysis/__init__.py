"""AI Analysis module - ML-based attack classification (FR-11)"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'model')
MODEL_PATH = os.path.join(MODEL_DIR, 'attack_classifier.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')

ATTACK_CATEGORIES = [
    'Normal',
    'Brute Force',
    'Port Scan',
    'Malware Activity',
    'SQL Injection',
    'Privilege Escalation',
    'DoS Indicators',
]


def create_mock_model():
    """Create and save a pre-trained model for demonstration purposes."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    np.random.seed(42)
    n_samples = 1000
    n_features = 8

    X = np.random.randn(n_samples, n_features)

    y = np.random.choice(len(ATTACK_CATEGORIES), n_samples, p=[
        0.40,   # Normal
        0.12,   # Brute Force
        0.10,   # Port Scan
        0.10,   # Malware Activity
        0.08,   # SQL Injection
        0.10,   # Privilege Escalation
        0.10,   # DoS Indicators
    ])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=10,
        random_state=42,
        class_weight='balanced',
    )
    model.fit(X_scaled, y)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    return model, scaler


def load_model():
    """Load pre-trained model and scaler. Create mock model if none exists."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return create_mock_model()

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler


def prepare_features_for_inference(df: pd.DataFrame, scaler) -> np.ndarray:
    """Prepare the 8-feature vector expected by the model."""
    feature_cols = [
        'hour', 'day_of_week', 'is_weekend', 'ip_first_octet',
        'ip_second_octet', 'attack_keyword_count', 'has_attack_keywords', 'line_length',
    ]

    available_cols = [c for c in feature_cols if c in df.columns]

    if not available_cols:
        return np.zeros((len(df), len(feature_cols)))

    X = df[available_cols].apply(pd.to_numeric, errors='coerce').fillna(0).values

    # Pad or trim to exactly 8 features
    if X.shape[1] < len(feature_cols):
        padding = np.zeros((X.shape[0], len(feature_cols) - X.shape[1]))
        X = np.hstack([X, padding])
    elif X.shape[1] > len(feature_cols):
        X = X[:, :len(feature_cols)]

    return scaler.transform(X)


def run_inference(model, scaler, df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Run model inference on processed data (FR-11).

    Returns a list of dicts, one per row, containing:
      - index, predicted_category, confidence, all_probabilities
    """
    X = prepare_features_for_inference(df, scaler)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    results = []
    for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
        confidence = float(np.max(probs))
        category = ATTACK_CATEGORIES[pred] if pred < len(ATTACK_CATEGORIES) else 'Unknown'

        prob_dict = {}
        for j in range(min(len(probs), len(ATTACK_CATEGORIES))):
            prob_dict[ATTACK_CATEGORIES[j]] = round(float(probs[j]), 4)

        results.append({
            'index': i,
            'predicted_category': category,
            'confidence': confidence,
            'all_probabilities': prob_dict,
        })

    return results
