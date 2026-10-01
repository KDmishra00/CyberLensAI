"""Preprocessing module - cleans and normalizes parsed data (FR-9, FR-10)"""
import pandas as pd
import numpy as np
from typing import Dict, Any


def remove_duplicates(df: pd.DataFrame, subset=None) -> pd.DataFrame:
    """Remove duplicate log entries (FR-9)."""
    return df.drop_duplicates(subset=subset, keep='first')


def normalize_timestamps(df: pd.DataFrame, timestamp_col: str = 'timestamp') -> pd.DataFrame:
    """Normalize timestamps to a consistent format (FR-10)."""
    df = df.copy()

    if timestamp_col not in df.columns:
        return df

    def parse_timestamp(ts):
        if pd.isna(ts):
            return None

        ts_str = str(ts).strip()

        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z',
            '%b %d %H:%M:%S',
        ]

        for fmt in formats:
            try:
                return pd.to_datetime(ts_str, format=fmt)
            except Exception:
                continue

        # Fallback — let pandas guess
        try:
            return pd.to_datetime(ts_str, utc=True)
        except Exception:
            return None

    df['normalized_timestamp'] = df[timestamp_col].apply(parse_timestamp)
    return df


def handle_missing_values(df: pd.DataFrame, strategy: str = 'fill') -> pd.DataFrame:
    """Handle missing values in the DataFrame."""
    df = df.copy()

    if strategy == 'drop':
        df = df.dropna()
    elif strategy == 'fill':
        for col in df.columns:
            if df[col].dtype in ['object', 'string']:
                df[col] = df[col].fillna('unknown')
            elif pd.api.types.is_numeric_dtype(df[col]):
                median_val = df[col].median() if not df[col].isna().all() else 0
                df[col] = df[col].fillna(median_val)
            elif pd.api.types.is_datetime64_any_dtype(df[col]):
                df[col] = df[col].fillna(pd.Timestamp.now())

    return df


def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    """Full preprocessing pipeline: dedup → normalize → fill."""
    df = remove_duplicates(df)
    df = normalize_timestamps(df)
    df = handle_missing_values(df, strategy='fill')
    return df


def get_preprocessing_stats(original_df: pd.DataFrame, processed_df: pd.DataFrame) -> Dict[str, Any]:
    """Get statistics about preprocessing changes."""
    return {
        'original_rows': len(original_df),
        'processed_rows': len(processed_df),
        'duplicates_removed': len(original_df) - len(processed_df),
        'columns': list(processed_df.columns),
    }
