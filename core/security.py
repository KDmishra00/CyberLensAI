"""Cybersecurity layer: severity assignment and mitigation lookup.

Severity is a transparent rule, not randomness:
  start from the base severity for the category (config.BASE_SEVERITY),
  +1 level if confidence >= 0.90 or the same source IP produced >= 20
  malicious events, -1 level if confidence < 0.65. Always clamped to
  Low / Medium / High / Critical.
"""
from __future__ import annotations

import json
from functools import lru_cache

import pandas as pd

import config


def _severity_index(level: str) -> int:
    return config.SEVERITY_LEVELS.index(level)


@lru_cache(maxsize=1)
def load_mitigations() -> dict:
    with open(config.MITIGATIONS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def assign_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Add a severity column using the documented rule."""
    base = df["predicted_category"].map(config.BASE_SEVERITY).fillna("Low")
    level = base.map(_severity_index).astype("int64")

    attack_rows = df["predicted_category"] != config.NORMAL_LABEL
    mal_by_ip = df[attack_rows].groupby("src_ip")["predicted_category"].transform("size")
    repeat_ip = pd.Series(False, index=df.index)
    repeat_ip.loc[attack_rows] = mal_by_ip >= config.SEVERITY_REPEAT_IP_THRESHOLD

    up = (df["confidence"] >= config.HIGH_CONFIDENCE_NOTE) | repeat_ip
    down = df["confidence"] < config.LOW_CONFIDENCE_NOTE
    level = (level + up.astype("int64") - (down & ~up).astype("int64")).clip(
        0, len(config.SEVERITY_LEVELS) - 1
    )

    out = df.copy()
    out["severity"] = level.map(dict(enumerate(config.SEVERITY_LEVELS)))
    # Normal rows have no severity at all - keeps tables honest.
    out.loc[~attack_rows, "severity"] = pd.NA
    return out


def mitigation_for(category: str) -> dict:
    """Mitigation steps + MITRE references for one category."""
    data = load_mitigations()
    entry = data.get(category, {"summary": "", "steps": [], "mitre": []})
    return {
        "category": category,
        "summary": entry.get("summary", ""),
        "steps": entry.get("steps", []),
        "mitre": entry.get("mitre", []),
    }


def mitigations_for_categories(categories: list[str]) -> list[dict]:
    return [mitigation_for(c) for c in categories if c in config.BASE_SEVERITY]
