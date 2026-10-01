"""Preprocessing: dedupe, normalise timestamps, fill missing values, and
compute the derived behavioural features the model needs.

The behavioural features (per-IP event counts, rates, port/user variety,
failure ratios and token indicators) are what let a single classifier see
Brute Force, Port Scan and DoS - those patterns only exist across rows,
not within one. Everything is vectorised pandas; no per-row Python loops
on the hot path.
"""
from __future__ import annotations

import urllib.parse

import pandas as pd

FAIL_WORDS = ("failed", "failure", "denied", "invalid", "unauthorized",
              "unauthorised", "authentication error", "401", "403")
SQL_TOKENS = ("'", "union select", "or 1=1", "1=1", "--", ";drop", "sleep(",
              "information_schema")
PRIV_TOKENS = ("sudo", "su -", "setuid", "chmod 777", "/etc/shadow",
               "/etc/passwd", "whoami /priv", "uac", "privilege",
               "administrators", "wheel group", "root group")
MALWARE_TOKENS = ("powershell -enc", "powershell -e ", "-enc ", "base64",
                  "mimikatz", "temp\\", "/tmp/", ".exe", "ransom", "beacon",
                  "c2", "trojan", "reverse shell", "vssadmin", "shadow copy")


def clean_text(series: pd.Series) -> pd.DataFrame:
    """Return (event_display, event_clean, event_url_decoded) copies of event text."""
    display = series.fillna("").astype("string")
    decoded = display.str.slice(0, 2000).map(
        lambda s: urllib.parse.unquote(s) if "%" in s else s
    )
    # Lowercase, collapsed whitespace, capped at 500 chars - this is what
    # the TF-IDF side of the model consumes.
    clean = decoded.str.lower().str.replace(r"\s+", " ", regex=True).str.slice(0, 500)
    return display.rename("event"), decoded.rename("event_decoded"), clean.rename("event_clean")


def _decode_timestamps(raw: pd.Series) -> tuple[pd.Series, int]:
    """Parse mixed timestamp formats to naive datetimes; count failures."""
    raw = raw.fillna("").astype("string").str.strip()
    # Epoch seconds (10-13 digits) first: pandas would read those as nanos.
    # astype("float64") collapses the nullable dtype to plain float so the
    # boolean masks below never contain pd.NA (NA silently drops rows in where()).
    numeric = pd.to_numeric(raw, errors="coerce").astype("float64")
    epoch = numeric.between(1e9, 1e11)  # 2001..5138 in seconds
    parsed_epoch = pd.to_datetime(numeric.where(epoch), unit="s", errors="coerce")

    text = raw.where(~epoch & raw.ne(""))
    # Strings like "Aug 14 10:22:31" (no year) must not reach the generic
    # parser - pandas would read them as year 1 or 1900. They go to the
    # fallback below, which assumes the current year.
    noyear = text.str.match(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", na=False)
    # Apache access log: 14/Aug/2026:10:22:31 +0000 - format="mixed" cannot
    # read this shape, so it gets its own explicit parser.
    apache = text.str.match(r"^\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$", na=False)
    apache_ts = pd.to_datetime(text.where(apache), format="%d/%b/%Y:%H:%M:%S %z",
                               errors="coerce", utc=True).dt.tz_convert(None)
    # utc=True gives one uniform tz-aware result even when the file mixes
    # naive and offset timestamps; we drop the tz right after.
    direct = pd.to_datetime(text.where(~noyear & ~apache), format="mixed", errors="coerce",
                            utc=True).dt.tz_convert(None)
    # Syslog dates carry no year (pandas would default to 1900): assume the
    # current year, which is the documented convention.
    fallback = pd.to_datetime(text.where(noyear), format="%b %d %H:%M:%S", errors="coerce")
    now = pd.Timestamp.now()

    def _with_current_year(ts):
        if pd.isna(ts):
            return ts
        try:
            return ts.replace(year=now.year)
        except ValueError:  # Feb 29 in a non-leap year
            return pd.NaT

    fallback = fallback.map(_with_current_year)

    combined = direct.fillna(apache_ts).fillna(fallback).fillna(parsed_epoch)
    unparsable = int((raw.ne("") & combined.isna()).sum())
    return combined.dt.floor("s"), unparsable


def _behavioural_features(df: pd.DataFrame) -> pd.DataFrame:
    """Per-IP and per-event features computed over the whole file."""
    ip = df["src_ip"].fillna("unknown").astype("string")
    feats = pd.DataFrame(index=df.index)

    ip_counts = ip.value_counts()
    feats["ip_event_count"] = ip.map(ip_counts).astype("int64")

    if df["timestamp"].notna().any():
        ts = df["timestamp"]
        valid = ts.notna()
        # Integer seconds since epoch, computed via timedelta so the result
        # does not depend on the datetime64 resolution pandas inferred
        # (astype("int64") would silently give ns, us or s).
        sec = (ts[valid] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
        sub = pd.DataFrame({"ip": ip[valid].astype(str), "sec": sec})
        sub = sub.sort_values(["ip", "sec"])
        grp = sub.groupby("ip", sort=False)["sec"]
        # Events from this IP within +/-30 s of this row, i.e. a one-minute
        # sliding window. searchsorted is vectorised per group.
        left = grp.transform(lambda s: s.searchsorted(s - 30, side="left"))
        right = grp.transform(lambda s: s.searchsorted(s + 30, side="right"))
        counts = (right - left).astype("int64")
        aligned = pd.Series(counts.to_numpy(), index=sub.index).sort_index()
        feats["ip_rate_1min"] = aligned.reindex(df.index).fillna(0).astype("int64")
    else:
        feats["ip_rate_1min"] = 0

    ports = df["dst_port"]
    has_port = ports.notna()
    port_pairs = pd.DataFrame({"ip": ip.where(has_port), "port": ports})
    distinct_ports = port_pairs.dropna().drop_duplicates().groupby("ip")["port"].size()
    feats["ip_unique_ports"] = ip.map(distinct_ports).fillna(0).astype("int64")

    text = df["event_clean"].fillna("")
    fail_mask = pd.Series(False, index=df.index)
    for word in FAIL_WORDS:
        fail_mask |= text.str.contains(word, regex=False)
    fail_by_ip = fail_mask.groupby(ip).transform("mean")
    feats["ip_fail_ratio"] = fail_by_ip.fillna(0).astype("float64")

    users = df["username"]
    has_user = users.notna()
    user_pairs = pd.DataFrame({"ip": ip.where(has_user), "user": users})
    distinct_users = user_pairs.dropna().drop_duplicates().groupby("ip")["user"].size()
    feats["ip_unique_users"] = ip.map(distinct_users).fillna(0).astype("int64")

    feats["event_length"] = text.str.len().astype("int64")
    feats["has_sql_tokens"] = _any_token(text, SQL_TOKENS).astype("int64")
    feats["has_priv_tokens"] = _any_token(text, PRIV_TOKENS).astype("int64")
    feats["has_malware_tokens"] = _any_token(text, MALWARE_TOKENS).astype("int64")
    return feats


def _any_token(text: pd.Series, tokens: tuple[str, ...]) -> pd.Series:
    mask = pd.Series(False, index=text.index)
    for token in tokens:
        mask |= text.str.contains(token, regex=False)
    return mask


def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Full preprocessing pass. Returns (clean_df, summary_dict)."""
    summary: dict = {"rows_in": int(len(df))}

    # Callers normally come from parser, which guarantees the canonical
    # columns; make sure of it so hand-built frames work too.
    for col, default in (("dst_ip", pd.NA), ("dst_port", pd.NA), ("username", pd.NA),
                         ("bytes", pd.NA), ("duration", pd.NA), ("status", ""),
                         ("event", "")):
        if col not in df.columns:
            df[col] = default

    # 1. Duplicates: identical timestamp+src_ip+event, or fully identical
    # rows (row_id excluded from the full-row check since it is unique).
    key_cols = ["timestamp", "src_ip", "event"]
    have_key = df["timestamp"].notna() & df["event"].notna()
    dup_mask = (df[have_key].duplicated(subset=key_cols, keep="first")
                .reindex(df.index, fill_value=False))
    dup_mask |= df.drop(columns=["row_id"]).duplicated(keep="first")
    df = df[~dup_mask].copy()
    summary["duplicates_removed"] = int(dup_mask.sum())

    # 2. Timestamps to one consistent format.
    df["timestamp"], unparsable = _decode_timestamps(df["timestamp"])
    summary["unparsable_timestamps"] = unparsable
    summary["timestamps_normalised"] = int(df["timestamp"].notna().sum())

    # 3. Missing values, counted before filling.
    summary["missing_before"] = {
        col: int(df[col].isna().sum())
        for col in ("timestamp", "src_ip", "dst_port", "username", "event", "bytes", "duration")
        if col in df.columns
    }
    df["src_ip"] = df["src_ip"].fillna("unknown")
    df["dst_ip"] = df.get("dst_ip", pd.Series(pd.NA, index=df.index)).fillna("unknown")
    df["username"] = df["username"].fillna("")
    df["event"] = df["event"].fillna("")
    for col in ("dst_port", "bytes", "duration"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["status"] = df["status"].fillna("").astype("string")

    # 4. Text copies: display, URL-decoded, model-clean.
    display, decoded, clean = clean_text(df["event"])
    df["event"] = display
    df["event_decoded"] = decoded
    df["event_clean"] = clean

    # 5. Behavioural features over the whole file.
    feats = _behavioural_features(df)
    df = pd.concat([df, feats], axis=1)

    summary["missing_filled"] = {
        "src_ip": summary["missing_before"].get("src_ip", 0),
        "username": summary["missing_before"].get("username", 0),
        "dst_port": summary["missing_before"].get("dst_port", 0),
        "bytes": summary["missing_before"].get("bytes", 0),
        "duration": summary["missing_before"].get("duration", 0),
    }
    summary["rows_out"] = int(len(df))
    return df, summary
