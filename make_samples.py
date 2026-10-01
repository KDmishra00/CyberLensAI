"""Generate the sample files in data/samples/ used for demos and tests.

Run:  python make_samples.py

The .pdf and >20 MB rejection samples are created on demand by the tests
and are deliberately not committed.
"""
from __future__ import annotations

import csv
import os
import random

from openpyxl import Workbook

from corpus import (BASE_TIME, block_bruteforce, block_dos, block_malware,
                    block_normal, block_portscan, block_privesc, block_sqli)

SAMPLES = os.path.join("data", "samples")


def _syslog_line(row: dict, rng: random.Random) -> str:
    event = row["event"]
    prefix = f"{row['prog']}: "
    if event.startswith(prefix):
        event = event[len(prefix):]
    ts = row["timestamp"]
    return (f"{ts:%b %d %H:%M:%S} {row['host']} "
            f"{row['prog']}[{rng.randint(100, 99999)}]: {event}")


def _apache_line(row: dict) -> str:
    request = row.get("request") or f"{row['event']} HTTP/1.1"
    ts = row["timestamp"]
    size = row.get("bytes") or 0
    status = row.get("status") or "200"
    return (f"{row['src_ip']} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "
            f'"{request}" {status} {size}')


def _sorted_rows(blocks: list[list[dict]]) -> list[dict]:
    rows = [r for block in blocks for r in block]
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def make_auth_log() -> None:
    rng = random.Random(7)
    rows = _sorted_rows([
        block_normal(rng, 4_200),
        block_bruteforce(rng), block_bruteforce(rng), block_bruteforce(rng),
        block_normal(rng, 300),
    ])
    with open(os.path.join(SAMPLES, "auth_bruteforce.log"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(_syslog_line(row, rng) + "\n")


def make_web_log() -> None:
    rng = random.Random(11)
    rows = _sorted_rows([
        block_normal(rng, 8_400),
        block_sqli(rng), block_sqli(rng), block_sqli(rng), block_sqli(rng),
        block_portscan(rng), block_portscan(rng),
        block_dos(rng),
        block_normal(rng, 600),
    ])
    with open(os.path.join(SAMPLES, "web_access.log"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(_apache_line(row) + "\n")


_TS_VARIANTS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d %b %Y %H:%M:%S")


def _csv_row(row: dict, i: int) -> dict:
    fmt = _TS_VARIANTS[i % len(_TS_VARIANTS)]
    return {
        "Datetime": row["timestamp"].strftime(fmt),
        "Source Address": row["src_ip"],
        "Destination Port": row.get("dst_port") or "",
        "Account": row.get("username") or "",
        "Log Message": row["event"],
        "Total Bytes": row.get("bytes") if row.get("bytes") is not None else "",
        "Flow Duration": row.get("duration") if row.get("duration") is not None else "",
        "Status Code": row.get("status") or "",
        "Attack Type": row["label"],
    }


def make_mixed_csv() -> None:
    rng = random.Random(13)
    rows = _sorted_rows([
        block_normal(rng, 700),
        block_bruteforce(rng), block_portscan(rng), block_malware(rng),
        block_sqli(rng), block_privesc(rng), block_dos(rng),
        block_normal(rng, 100),
    ])
    with open(os.path.join(SAMPLES, "mixed_incidents.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(_csv_row(rows[0], 0).keys()))
        writer.writeheader()
        for i, row in enumerate(rows):
            writer.writerow(_csv_row(row, i))


def make_clean_csv() -> None:
    rng = random.Random(17)
    rows = _sorted_rows([block_normal(rng, 900)])
    with open(os.path.join(SAMPLES, "clean_normal.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "src_ip", "dst_port", "username",
                         "message", "bytes", "status"])
        for row in rows:
            writer.writerow([
                row["timestamp"].strftime(_TS_VARIANTS[0]),
                row["src_ip"], row.get("dst_port") or "", row.get("username") or "",
                row["event"], row.get("bytes") if row.get("bytes") is not None else "",
                row.get("status") or "",
            ])


def make_flows_xlsx() -> None:
    rng = random.Random(19)
    rows = _sorted_rows([
        block_normal(rng, 900),
        block_portscan(rng), block_dos(rng), block_normal(rng, 100),
    ])
    wb = Workbook()
    ws = wb.active
    ws.title = "flows"
    ws.append(["start_time", "src_addr", "dst_addr", "dst_port", "proto",
               "packets", "flow_bytes", "flow_duration", "msg"])
    for row in rows:
        ws.append([
            row["timestamp"].strftime(_TS_VARIANTS[0]),
            row["src_ip"], row.get("dst_ip") or f"10.0.{rng.randint(0, 5)}.{rng.randint(2, 250)}",
            row.get("dst_port") or rng.choice([80, 443]),
            rng.choice([6, 6, 6, 17]),
            rng.randint(4, 60),
            row.get("bytes") if row.get("bytes") is not None else rng.randint(100, 50_000),
            row.get("duration") if row.get("duration") is not None else round(rng.uniform(0.01, 20), 3),
            row["event"],
        ])
    wb.save(os.path.join(SAMPLES, "network_flows.xlsx"))


def make_broken_csv() -> None:
    """Mostly readable, with duplicated rows, blanks and latin-1 characters."""
    rng = random.Random(23)
    rows = block_normal(rng, 120) + block_bruteforce(rng)
    lines = ["time,ip,msg,bytes"]
    for i, row in enumerate(rows):
        if i % 17 == 0:
            lines.append("")                                   # blank line
        if i % 23 == 0:
            lines.append("this line is not a csv row at all")  # junk
        event = row["event"]
        if i % 29 == 0:
            event = f"caf\u00e9 r\u00e9sum\u00e9 probe {event}"  # latin-1 text
        lines.append(",".join([
            row["timestamp"].strftime(_TS_VARIANTS[0]),
            row["src_ip"], f'"{event}"', str(row.get("bytes") or ""),
        ]))
        if i % 31 == 0 and lines[-1]:
            lines.append(lines[-1])                            # exact duplicate
    with open(os.path.join(SAMPLES, "broken.csv"), "w", encoding="latin-1") as fh:
        fh.write("\n".join(lines))


def main() -> None:
    os.makedirs(SAMPLES, exist_ok=True)
    make_auth_log()
    make_web_log()
    make_mixed_csv()
    make_clean_csv()
    make_flows_xlsx()
    make_broken_csv()
    for name in sorted(os.listdir(SAMPLES)):
        size = os.path.getsize(os.path.join(SAMPLES, name))
        print(f"  {name:24s} {size / 1024:8.1f} KB")


if __name__ == "__main__":
    main()
