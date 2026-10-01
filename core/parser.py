"""Parsing: CSV/XLSX tables or raw log text -> canonical records.

Whatever the input shape, the output is a pandas DataFrame with the
canonical columns from the spec (row_id, timestamp, src_ip, dst_ip,
dst_port, username, event, bytes, duration, status, label_original)
plus any extra numeric columns kept for display.

Nothing here ever evaluates file content; every extraction is a regex or
a pandas read. Unreadable log lines are kept with what was salvaged and
counted, so the preview can report a parse success rate honestly.
"""
from __future__ import annotations

import os
import re

import pandas as pd

from config import MAX_ROWS

CANONICAL_COLUMNS = [
    "row_id", "timestamp", "src_ip", "dst_ip", "dst_port",
    "username", "event", "bytes", "duration", "status", "label_original",
]

# Names seen in the wild for each canonical column. Matching ignores case,
# spaces, underscores and dots. Order matters: first hit wins, so specific
# names ("src_ip") are listed before generic ones ("ip").
COLUMN_ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "date", "date/time", "@timestamp", "ts", "eventtime",
                   "event time", "date time", "start time", "record time"],
    "src_ip": ["src ip", "source ip", "srcip", "source address", "sourceaddress", "client ip",
               "clientip", "remote addr", "remoteaddr", "src addr", "srcaddr", "ip", "source"],
    "dst_ip": ["dst ip", "dest ip", "destination ip", "dstip", "destination address",
               "destinationaddress", "dst addr", "dstaddr", "server ip"],
    "dst_port": ["dst port", "dest port", "destination port", "dstport", "dport", "port"],
    "username": ["username", "user name", "user", "account", "login", "loginname", "authuser"],
    "event": ["event", "message", "msg", "description", "details", "info", "log", "text",
              "request", "uri", "url", "path", "query", "alert", "signature",
              "log message", "log line", "event description"],
    "bytes": ["bytes", "total bytes", "totalbytes", "length", "size", "flow bytes",
              "flowbytes", "content length", "responselen", "response length"],
    "duration": ["duration", "flow duration", "flowduration", "elapsed", "elapsed time"],
    "status": ["status", "status code", "statuscode", "http status", "response code",
               "responsecode", "result", "outcome"],
    "label_original": ["label", "class", "attack", "attack cat", "attackcat", "attack type",
                       "attacktype", "category", "type"],
}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+[^"]*"')


class ParseError(ValueError):
    """The file cannot be turned into records at all."""


def _norm_key(name: str) -> str:
    return re.sub(r"[ _.\-]+", " ", str(name).strip().lower())


def map_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Rename columns onto canonical names using the alias table.

    Returns (df_renamed, mapping) where mapping is {canonical: original}.
    """
    normalized = {_norm_key(c): c for c in df.columns}
    mapping: dict[str, str] = {}
    renames: dict[str, str] = {}
    used_originals: set[str] = set()
    for canonical, aliases in COLUMN_ALIASES.items():
        if canonical in renames.values():
            continue
        for alias in aliases:
            original = normalized.get(alias)
            if original is not None and original not in used_originals:
                renames[original] = canonical
                mapping[canonical] = original
                used_originals.add(original)
                break
    return df.rename(columns=renames), mapping


def _to_numeric(series: pd.Series) -> pd.Series:
    """Coerce to numeric, stripping commas and units; failures become NaN."""
    return pd.to_numeric(
        series.astype("string").str.replace(r"[,\s]", "", regex=True).str.replace(r"[A-Za-z]+$", "", regex=True),
        errors="coerce",
    )


def _status_text(series: pd.Series) -> pd.Series:
    return series.where(series.notna(), "").astype(str).replace({"": None, "nan": None})


def parse_tabular(path: str, ext: str) -> tuple[pd.DataFrame, dict]:
    """Parse a CSV or XLSX file into canonical records."""
    meta: dict = {}
    if ext == ".xlsx":
        xl = pd.ExcelFile(path, engine="openpyxl")
        sheet_name = xl.sheet_names[0]
        for name in xl.sheet_names:
            probe = xl.parse(name, nrows=2)
            if not probe.empty:
                sheet_name = name
                break
        df = xl.parse(sheet_name)
        meta["sheet"] = sheet_name
        if len(xl.sheet_names) > 1:
            meta["note"] = f"Workbook has {len(xl.sheet_names)} sheets; analysed the first non-empty one ({sheet_name})."
    else:
        df = _read_csv_lenient(path)

    if df.empty:
        raise ParseError("This file has a header but no data rows.")

    original_columns = list(df.columns)
    df, mapping = map_columns(df)

    # Synthesise an event column from leftover text columns if none mapped.
    if "event" not in df.columns:
        leftovers = [c for c in df.columns
                     if c not in CANONICAL_COLUMNS and df[c].dtype == object]
        if leftovers:
            df["event"] = (
                df[leftovers].astype("string")
                .agg(" | ".join, axis=1)
                .str.replace(r"\s+", " ", regex=True)
                .str.strip(" |")
                .replace("", pd.NA)
            )
            mapping["event"] = " + ".join(leftovers)

    numeric_extra = [
        c for c in df.columns
        if c not in CANONICAL_COLUMNS and pd.api.types.is_numeric_dtype(df[c])
    ][:20]
    extras = df[numeric_extra].copy() if numeric_extra else pd.DataFrame(index=df.index)
    extras.columns = [f"extra_{c}" for c in numeric_extra]

    if "event" not in df.columns and not numeric_extra:
        raise ParseError(
            "We could not find anything to analyse in this file. CyberLens looks for a "
            "message/description/event column, or numeric columns such as bytes, duration or port. "
            f"It found only: {', '.join(map(str, original_columns))}."
        )

    out = pd.DataFrame(index=df.index)
    out["row_id"] = range(1, len(df) + 1)
    out["timestamp"] = df["timestamp"] if "timestamp" in df.columns else pd.NaT
    for col in ("src_ip", "dst_ip", "username", "status", "label_original"):
        out[col] = df[col].astype("string").str.strip().replace({"": pd.NA, "nan": pd.NA}) if col in df.columns else pd.NA
    out["dst_port"] = _to_numeric(df["dst_port"]) if "dst_port" in df.columns else pd.NA
    out["bytes"] = _to_numeric(df["bytes"]) if "bytes" in df.columns else pd.NA
    out["duration"] = _to_numeric(df["duration"]) if "duration" in df.columns else pd.NA
    out["event"] = df["event"].astype("string") if "event" in df.columns else pd.NA
    out = pd.concat([out, extras], axis=1)

    # A single text column of log lines labelled .csv is still a log file.
    if out["event"].notna().all() and len(out.columns) <= 6:
        meta["log_like"] = True
    meta["column_mapping"] = mapping
    meta["row_count"] = int(len(out))
    return out, meta


def _read_csv_lenient(path: str) -> pd.DataFrame:
    """Read CSV trying encodings and delimiters until one produces columns."""
    last_error: Exception | None = None
    for encoding in ("utf-8", "latin-1"):
        for sep in (None, ",", ";", "\t"):
            try:
                df = pd.read_csv(
                    path, encoding=encoding, sep=sep, engine="python",
                    on_bad_lines="skip", nrows=MAX_ROWS,
                )
            except (UnicodeDecodeError, pd.errors.ParserError, ValueError) as exc:
                last_error = exc
                continue
            if df.shape[1] >= 2:
                return df
            # A single wide column usually means the wrong delimiter won.
            wide = df[df.columns[0]].astype("string")
            if wide.str.contains(",").any():
                retry = pd.read_csv(
                    path, encoding=encoding, sep=",", engine="python",
                    on_bad_lines="skip", nrows=MAX_ROWS,
                )
                if retry.shape[1] >= 2:
                    return retry
                return df
            return df
    raise ParseError(f"This CSV could not be parsed: {last_error or 'unknown reason'}")


# --- Log line parsing --------------------------------------------------------

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"

# 1) Syslog / auth log style:  Aug 14 10:22:31 host sshd[1234]: message
_SYSLOG_RE = re.compile(
    rf"^(?P<ts>(?:{_MONTHS})\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[\w\-.]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
# 2) Apache/Nginx common & combined:
#    1.2.3.4 - - [14/Aug/2026:10:22:31 +0000] "GET /x HTTP/1.1" 200 512 "ref" "ua"
_APACHE_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
# 3) ISO application logs, optional level, key=value pairs:
#    2026-08-14 10:22:31,123 WARN user=admin ip=10.0.0.4 msg="..."
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*"
    r"(?:(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|NOTICE|FATAL)\s+)?(?P<rest>.*)$"
)

_KV_PATTERNS = [
    (re.compile(r"\b(?:src|src_ip|source_ip|source|client|client_ip|remote)[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})"), "src_ip"),
    (re.compile(r"\b(?:dst|dst_ip|dest_ip|dest|server)[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})"), "dst_ip"),
    (re.compile(r"\b(?:dport|dst_port|dest_port|port)[:=]\s*(\d{1,5})"), "dst_port"),
    (re.compile(r"\b(?:bytes|size|len|length)[:=]\s*(\d{1,12})"), "bytes"),
    (re.compile(r"\b(?:duration|elapsed)[:=]\s*([\d.]{1,12})"), "duration"),
    (re.compile(r"\b(?:status|code)[:=]\s*(\d{3})"), "status"),
]
_KV_USER_RE = re.compile(r"\b(?:user|username|account|login)[:=]\s*([\w.@-]{1,64})")


def _extract_kv(text: str, out: dict) -> None:
    for pattern, field in _KV_PATTERNS:
        match = pattern.search(text)
        if match:
            out.setdefault(field, match.group(1))
    user = _KV_USER_RE.search(text)
    if user:
        out.setdefault("username", user.group(1))


def _parse_line(line: str) -> dict | None:
    """Best-effort parse of one log line. Returns None only for empty lines."""
    fields: dict = {"event": line.strip(), "format": "generic"}
    stripped = line.strip()
    if not stripped:
        return None

    # Standard date prefixes shared by several formats get pulled off first.
    timestamp = None

    syslog = _SYSLOG_RE.match(stripped)
    apache = _APACHE_RE.match(stripped)
    iso = _ISO_RE.match(stripped)

    if apache:
        fields.update(format="apache", src_ip=apache.group("ip"),
                      username=None if apache.group("user") == "-" else apache.group("user"),
                      status=apache.group("status"))
        size = apache.group("size")
        if size.isdigit():
            fields["bytes"] = int(size)
        timestamp = apache.group("ts")
        request = apache.group("request") or ""
        fields["event"] = request
        url_match = _URL_RE.search(stripped)
        if url_match:
            fields["event"] = f'{url_match.group("method")} {url_match.group("url")}'
        port_match = re.search(r":(\d{1,5})(?:/\S*)?\s+HTTP", request)
        if port_match:
            fields["dst_port"] = port_match.group(1)
    elif syslog:
        fields.update(format="syslog", host=syslog.group("host"), prog=syslog.group("prog"))
        timestamp = syslog.group("ts")
        msg = syslog.group("msg")
        fields["event"] = f"{syslog.group('prog')}: {msg}"
        _extract_kv(msg, fields)
        ip = _IPV4_RE.search(msg)
        if ip and "src_ip" not in fields:
            fields["src_ip"] = ip.group(0)
        port = re.search(r"\bport (\d{1,5})\b", msg)
        if port:
            fields.setdefault("dst_port", port.group(1))
        user = re.search(r"\bfor (?:invalid user |user )?(\w[\w.@-]{0,63})", msg)
        if user and user.group(1).lower() not in ("from", "port", "invalid", "user"):
            fields.setdefault("username", user.group(1))
        if "invalid user" in msg.lower():
            fields["username"] = re.search(r"invalid user (\S+)", msg, re.I)
            fields["username"] = fields["username"].group(1) if fields["username"] else fields.get("username")
    elif iso:
        fields.update(format="iso")
        timestamp = iso.group("ts")
        rest = iso.group("rest")
        fields["event"] = rest
        _extract_kv(rest, fields)
        ip = _IPV4_RE.search(rest)
        if ip and "src_ip" not in fields:
            fields["src_ip"] = ip.group(0)
    else:
        # Generic fallback: timestamp regexes, IPv4, user= pattern.
        for pattern in (
            r"\b\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
            rf"\b(?:{_MONTHS})\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\b",
            r"\b\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b",
            r"\b\d{10}(?:\.\d+)?\b",
        ):
            ts_match = re.search(pattern, stripped)
            if ts_match:
                timestamp = ts_match.group(0)
                fields["event"] = stripped.replace(timestamp, "", 1).strip() or stripped
                break
        ip = _IPV4_RE.search(stripped)
        if ip:
            fields["src_ip"] = ip.group(0)
        _extract_kv(stripped, fields)
        user = re.search(r"\buser[=:\s]+(\w[\w.@-]{0,63})", stripped, re.I)
        if user:
            fields.setdefault("username", user.group(1))

    fields["timestamp"] = timestamp
    return fields


def parse_log(path: str) -> tuple[pd.DataFrame, dict]:
    """Parse a raw log file line by line into canonical records."""
    last_error: Exception | None = None
    lines: list[str] = []
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=encoding, errors="strict") as fh:
                lines = fh.read().splitlines()
            break
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    if not lines and last_error:
        raise ParseError("This log file could not be decoded as text.")

    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        raise ParseError("This log file has no non-empty lines.")
    if len(non_empty) > MAX_ROWS:
        non_empty = non_empty[:MAX_ROWS]

    records = []
    failed_lines = 0
    for line_no, line in enumerate(non_empty, start=1):
        fields = _parse_line(line)
        if fields is None:
            continue
        if not (fields.get("timestamp") or fields.get("src_ip")):
            failed_lines += 1
        records.append(fields)

    df = pd.DataFrame(records)
    if df.empty:
        raise ParseError("No line in this file looked like a log entry.")

    out = pd.DataFrame(index=df.index)
    out["row_id"] = range(1, len(df) + 1)
    out["timestamp"] = df["timestamp"]
    for col in ("src_ip", "dst_ip", "username", "status"):
        out[col] = df[col] if col in df.columns else pd.NA
    for col in ("dst_port", "bytes", "duration"):
        out[col] = pd.to_numeric(df[col], errors="coerce") if col in df.columns else pd.NA
    out["event"] = df["event"].astype("string")
    out["label_original"] = pd.NA

    formats = df["format"].value_counts().to_dict() if "format" in df.columns else {}
    total = int(len(out))
    parsed_ok = int((out["event"].notna() & (out["timestamp"].notna() | out["src_ip"].notna())).sum())
    meta = {
        "row_count": total,
        "formats": formats,
        "parse_success_rate": round(parsed_ok / total, 4) if total else 0.0,
        "failed_lines": failed_lines,
        "encoding": encoding,
    }
    return out, meta


def parse_file(path: str, ext: str, original_name: str) -> tuple[pd.DataFrame, dict]:
    """Dispatch on extension; returns (records, metadata) for the preview."""
    if ext == ".log":
        df, meta = parse_log(path)
        meta["detected_type"] = "Raw log (.log)"
        meta["log_like"] = True
        return df, meta
    df, meta = parse_tabular(path, ext)
    meta["detected_type"] = "Excel workbook (.xlsx)" if ext == ".xlsx" else "CSV / tabular (.csv)"
    meta["filename"] = os.path.basename(original_name)
    if meta.pop("log_like", False):
        meta["detected_type"] += " - single text column, read as log lines"
        df, log_meta = parse_log(path)
        meta["detected_type"] = "Text file (.csv) - read as log lines"
        meta.update({"formats": log_meta["formats"], "parse_success_rate": log_meta["parse_success_rate"],
                     "failed_lines": log_meta["failed_lines"]})
    return df, meta
