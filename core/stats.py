"""Statistics for the dashboard and the report.

All numbers here come from the analysed DataFrame - nothing is stored or
hardcoded. The timeline picks its bucket size (minute/hour/day) from the
observed time span so the chart lands in the 10-60 point range.
"""
from __future__ import annotations

import pandas as pd

import config


def compute_stats(df: pd.DataFrame, preprocessing_summary: dict | None = None) -> dict:
    """Compute every figure the dashboard and report need."""
    total = int(len(df))
    attack_mask = df["predicted_category"] != config.NORMAL_LABEL
    attacks = int(attack_mask.sum())

    category_counts = (
        df.loc[attack_mask, "predicted_category"].value_counts().to_dict()
        if attacks else {}
    )
    category_pct = {k: round(v * 100.0 / attacks, 1) for k, v in category_counts.items()} if attacks else {}

    severity_counts = (
        df.loc[attack_mask, "severity"].value_counts().reindex(config.SEVERITY_LEVELS).fillna(0).astype(int).to_dict()
        if attacks else {s: 0 for s in config.SEVERITY_LEVELS}
    )

    # Top source IPs by attack count, with their dominant category.
    top_ips: list[dict] = []
    if attacks:
        attacks_df = df.loc[attack_mask]
        sev_rank = attacks_df["severity"].map(
            {name: i for i, name in enumerate(config.SEVERITY_LEVELS)}
        )
        grouped = attacks_df.assign(_sev=sev_rank).groupby("src_ip")
        ip_stats = grouped.agg(
            attacks=("predicted_category", "size"),
            dominant=("predicted_category", lambda s: s.mode().iat[0]),
            max_sev=("_sev", "max"),
        )
        sev_name = dict(enumerate(config.SEVERITY_LEVELS))
        ip_stats["max_severity"] = ip_stats["max_sev"].map(sev_name)
        top_ips = (
            ip_stats.sort_values(["attacks", "max_sev"], ascending=False)
            .head(5).reset_index()[["src_ip", "attacks", "dominant", "max_severity"]]
            .to_dict("records")
        )

    top_targets = _top_targets(df, attack_mask)

    timeline, timeline_note = _timeline(df, attack_mask)

    detections = _top_detections(df, attack_mask)

    return {
        "total_records": total,
        "total_attacks": attacks,
        "total_normal": total - attacks,
        "attack_pct": round(attacks * 100.0 / total, 1) if total else 0.0,
        "category_counts": category_counts,
        "category_pct": category_pct,
        "severity_counts": severity_counts,
        "top_ips": top_ips,
        "top_targets": top_targets,
        "low_confidence_count": int(df["low_confidence"].sum()),
        "timeline": timeline,
        "timeline_note": timeline_note,
        "detections": detections,
        "preprocessing": preprocessing_summary or {},
    }


def _top_targets(df: pd.DataFrame, attack_mask: pd.Series) -> dict:
    attacks_df = df.loc[attack_mask]
    top_users: list[dict] = []
    if attacks_df["username"].ne("").any():
        users = attacks_df.loc[attacks_df["username"].ne(""), "username"].value_counts().head(5)
        top_users = [{"name": k, "count": int(v)} for k, v in users.items()]
    # Only service ports count as "targeted"; client-side ephemeral ports
    # (IANA dynamic range 49152-65535) would make this list meaningless.
    top_ports: list[dict] = []
    ports = attacks_df.loc[attacks_df["dst_port"].notna() & (attacks_df["dst_port"] < 49152), "dst_port"]
    if not ports.empty:
        top_ports = [{"port": int(k), "count": int(v)} for k, v in ports.value_counts().head(5).items()]
    return {"usernames": top_users, "ports": top_ports}


def _timeline(df: pd.DataFrame, attack_mask: pd.Series) -> tuple[list[dict], str | None]:
    """Attacks bucketed by minute, hour or day - whichever yields <= 60 buckets."""
    if not attack_mask.any():
        return [], "No attacks were detected, so there is nothing to plot."
    ts = df["timestamp"]
    if ts.notna().sum() < 5:
        return [], "Most timestamps could not be read, so there is no timeline for this file."
    span_seconds = (ts.max() - ts.min()).total_seconds()
    if span_seconds <= 0:
        return [], "All events share one timestamp, so there is no timeline to draw."

    for freq, unit, unit_seconds in (("min", "minute", 60), ("h", "hour", 3600), ("D", "day", 86400)):
        if span_seconds / unit_seconds <= 60:
            break

    attacks_ts = df.loc[attack_mask & ts.notna(), "timestamp"]
    if attacks_ts.empty:
        return [], "Attacks were found but none carry a usable timestamp."

    counts = attacks_ts.dt.floor(freq).value_counts().sort_index()
    fmt = "%Y-%m-%d" if freq == "D" else "%Y-%m-%d %H:%M"
    timeline = [{"time": t.strftime(fmt), "count": int(c)} for t, c in counts.items()]
    return timeline, f"Bucketed per {unit}."


def _top_detections(df: pd.DataFrame, attack_mask: pd.Series) -> list[dict]:
    """Top 25 most severe detections: by severity level, then confidence."""
    sev_rank = df["severity"].map(
        {name: i for i, name in enumerate(config.SEVERITY_LEVELS)}
    )
    rank = pd.DataFrame({"sev": sev_rank, "conf": df["confidence"]})
    rank = rank.fillna({"sev": -1})
    order = rank.sort_values(["sev", "conf"], ascending=False).index[:25]

    rows = []
    for idx in order:
        row = df.loc[idx]
        if not attack_mask.loc[idx]:
            continue
        rows.append({
            "row_id": int(row["row_id"]),
            "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(row["timestamp"]) else None,
            "src_ip": row["src_ip"],
            "username": row["username"] or "",
            "predicted_category": row["predicted_category"],
            "severity": row["severity"],
            "confidence": float(row["confidence"]),
            "event": str(row["event"])[:300],
        })
    return rows
