"""Parsing module - parses CSV, XLSX, and LOG files into structured data (FR-5 to FR-8)"""
import pandas as pd
import re
import os
from typing import Dict, Any


# Regex patterns for log field extraction (FR-5 through FR-8)
LOG_PATTERNS = {
    'timestamp': re.compile(
        r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|'
        r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}[+-]\d{4}|'
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|'
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
    ),
    'ip': re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ),
    'username': re.compile(
        r'(?:user|username|login|account)[\s:=]+([a-zA-Z0-9._-]+)|'
        r'(?:for|from)\s+([a-zA-Z0-9._-]+)\s+(?:from|at|\(|$)'
    ),
    'event': re.compile(
        r'(?:error|fail|warning|info|debug|critical|alert|notice|emergency|'
        r'attack|intrusion|breach|scan|brute|force|injection|malware|dos|ddos|'
        r'privilege|escalation|port|unauthorized|access|denied|blocked|suspicious|anomaly)',
        re.IGNORECASE
    ),
}


def parse_log_file(filepath: str) -> pd.DataFrame:
    """Parse raw log file and extract structured fields (FR-5 to FR-8)."""
    records = []

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            record = {
                'raw_line': line,
                'line_number': line_num,
            }

            # FR-5: Extract timestamps
            ts_match = LOG_PATTERNS['timestamp'].search(line)
            record['timestamp'] = ts_match.group(1) if ts_match else None

            # FR-6: Extract IP addresses
            ip_matches = LOG_PATTERNS['ip'].findall(line)
            record['ip_addresses'] = ', '.join(ip_matches) if ip_matches else None
            record['source_ip'] = ip_matches[0] if ip_matches else None

            # FR-7: Extract usernames
            user_match = LOG_PATTERNS['username'].search(line)
            if user_match:
                record['username'] = user_match.group(1) or user_match.group(2)
            else:
                record['username'] = None

            # FR-8: Extract event descriptions / keywords
            event_matches = LOG_PATTERNS['event'].findall(line)
            record['event_keywords'] = ', '.join(set(event_matches)) if event_matches else None
            record['event_description'] = line[:500]

            records.append(record)

    if not records:
        return pd.DataFrame(columns=[
            'raw_line', 'line_number', 'timestamp', 'ip_addresses',
            'source_ip', 'username', 'event_keywords', 'event_description'
        ])

    return pd.DataFrame(records)


def parse_csv_file(filepath: str) -> pd.DataFrame:
    """Parse CSV file into a DataFrame (FR-2)."""
    try:
        return pd.read_csv(filepath, encoding='utf-8')
    except UnicodeDecodeError:
        return pd.read_csv(filepath, encoding='latin-1')


def parse_xlsx_file(filepath: str) -> pd.DataFrame:
    """Parse XLSX file into a DataFrame (FR-1)."""
    return pd.read_excel(filepath, engine='openpyxl')


def parse_dataset(filepath: str) -> pd.DataFrame:
    """Parse dataset based on file extension."""
    ext = filepath.rsplit('.', 1)[1].lower()

    if ext == 'csv':
        return parse_csv_file(filepath)
    elif ext == 'xlsx':
        return parse_xlsx_file(filepath)
    elif ext == 'log':
        return parse_log_file(filepath)
    else:
        raise ValueError(f'Unsupported file format: .{ext}')


def get_dataset_preview(filepath: str, n_rows: int = 20) -> Dict[str, Any]:
    """Get preview information for dataset (SRS §3.1c)."""
    df = parse_dataset(filepath)

    missing_values = df.isnull().sum().to_dict()
    dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}

    # Sample rows for display
    preview_rows = df.head(n_rows).fillna('').to_dict('records')

    return {
        'filename': os.path.basename(filepath),
        'row_count': len(df),
        'column_count': len(df.columns),
        'columns': list(df.columns),
        'dtypes': dtypes,
        'missing_values': missing_values,
        'preview_rows': preview_rows,
    }


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract the 8 features expected by the pre-trained ML model."""
    features = pd.DataFrame()

    # Time features from timestamp column
    if 'timestamp' in df.columns:
        try:
            timestamps = pd.to_datetime(df['timestamp'], errors='coerce')
            features['hour'] = timestamps.dt.hour.fillna(0).astype(int)
            features['day_of_week'] = timestamps.dt.dayofweek.fillna(0).astype(int)
            features['is_weekend'] = (features['day_of_week'] >= 5).astype(int)
        except Exception:
            features['hour'] = 0
            features['day_of_week'] = 0
            features['is_weekend'] = 0
    else:
        features['hour'] = 0
        features['day_of_week'] = 0
        features['is_weekend'] = 0

    # IP features
    if 'source_ip' in df.columns:
        ip_parts = df['source_ip'].astype(str).str.split('.', expand=True)
        if ip_parts.shape[1] >= 2:
            features['ip_first_octet'] = pd.to_numeric(ip_parts[0], errors='coerce').fillna(0).astype(int)
            features['ip_second_octet'] = pd.to_numeric(ip_parts[1], errors='coerce').fillna(0).astype(int)
        else:
            features['ip_first_octet'] = 0
            features['ip_second_octet'] = 0
    else:
        features['ip_first_octet'] = 0
        features['ip_second_octet'] = 0

    # Attack keyword features
    attack_keywords = [
        'attack', 'intrusion', 'breach', 'scan', 'brute', 'force',
        'injection', 'malware', 'dos', 'ddos', 'privilege', 'escalation',
        'unauthorized', 'denied', 'blocked', 'suspicious', 'anomaly',
    ]

    if 'event_keywords' in df.columns:
        def count_attack_keywords(keywords):
            if pd.isna(keywords):
                return 0
            kw_lower = str(keywords).lower()
            return sum(1 for ak in attack_keywords if ak in kw_lower)

        features['attack_keyword_count'] = df['event_keywords'].apply(count_attack_keywords)
        features['has_attack_keywords'] = (features['attack_keyword_count'] > 0).astype(int)
    else:
        features['attack_keyword_count'] = 0
        features['has_attack_keywords'] = 0

    # Line length feature
    if 'raw_line' in df.columns:
        features['line_length'] = df['raw_line'].astype(str).str.len().fillna(0).astype(int)
    else:
        features['line_length'] = 0

    features = features.fillna(0)
    return features
