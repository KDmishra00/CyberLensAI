"""CyberLens AI - central configuration.

Every tunable the rest of the app depends on lives here so the numbers are
stated once and can be reasoned about in one place.
"""
import os

# --- Paths -----------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(BASE_DIR, "tmp")
MODEL_PATH = os.path.join(BASE_DIR, "models", "cyberlens_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "models", "metrics.json")
MITIGATIONS_PATH = os.path.join(BASE_DIR, "data", "mitigations.json")
SAMPLES_DIR = os.path.join(BASE_DIR, "data", "samples")

# --- Upload limits ----------------------------------------------------------
MAX_CONTENT_LENGTH = 20 * 1024 * 1024          # 20 MB hard limit (Flask)
MAX_UPLOAD_BYTES = MAX_CONTENT_LENGTH
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".log"}
MAX_ROWS = 500_000                              # zip-bomb / runaway-row guard
MAX_XLSX_DECOMPRESSED = 200 * 1024 * 1024      # cap on total decompressed XML

# --- Inference / analysis thresholds ---------------------------------------
CONFIDENCE_ANOMALY_THRESHOLD = 0.55   # below this an "attack" prediction stays Normal
LOW_CONFIDENCE_NOTE = 0.65            # severity drops a level below this
HIGH_CONFIDENCE_NOTE = 0.90           # severity rises a level at/above this

# --- Severity ---------------------------------------------------------------
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

# Base severity per attack category, then adjustments (documented in README
# and shown on the report page). Order matters: the rule always starts from
# the base, applies at most one step up and one step down.
BASE_SEVERITY = {
    "Malware Activity": "Critical",
    "SQL Injection": "High",
    "Privilege Escalation": "High",
    "DoS Indicators": "High",
    "Brute Force": "Medium",
    "Port Scan": "Low",
}

# Events from one IP needed before "repeated attacker" bumps severity a level.
SEVERITY_REPEAT_IP_THRESHOLD = 20

# --- Attack categories ------------------------------------------------------
ATTACK_CATEGORIES = [
    "Brute Force",
    "Port Scan",
    "Malware Activity",
    "SQL Injection",
    "Privilege Escalation",
    "DoS Indicators",
]
NORMAL_LABEL = "Normal"

# --- App --------------------------------------------------------------------
HOST = "127.0.0.1"
# 5000 is taken by AirPlay Receiver on modern macOS, so 5001 is the default.
PORT = int(os.environ.get("CYBERLENS_PORT", "5001"))
DEBUG = os.environ.get("CYBERLENS_DEBUG", "0") == "1"

# tmp/ folders older than this are swept in the background.
TMP_MAX_AGE_SECONDS = 60 * 60
CLEANUP_INTERVAL_SECONDS = 10 * 60

# Feature columns the model consumes (canonical + derived, built in preprocess).
MODEL_NUMERIC_FEATURES = [
    "bytes", "duration", "dst_port",
    "ip_event_count", "ip_rate_1min", "ip_unique_ports",
    "ip_fail_ratio", "ip_unique_users",
    "event_length", "has_sql_tokens", "has_priv_tokens", "has_malware_tokens",
]
TEXT_FEATURE = "event_clean"
