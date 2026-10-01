"""End-to-end tests for the CyberLens pipeline.

Run:  python -m pytest tests/ -v

These hit the real modules (no web framework needed except for the app
tests, which use Flask's test client) and print the measured log parse
success rate so the 95% reliability requirement is visible in the output.
"""
from __future__ import annotations

import io
import os
import shutil
import sys
import zipfile

import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from core import analyzer, parser, preprocess, report, security, stats
from core.upload import UploadError, validate_extension

SAMPLES = config.SAMPLES_DIR


# --- FR-1/2/3: accepted and rejected inputs ----------------------------------

def test_allowed_extensions_accepted():
    for name in ("a.csv", "b.xlsx", "c.log"):
        assert validate_extension(name) == os.path.splitext(name)[1]


def test_unsupported_extension_rejected():
    with pytest.raises(UploadError) as excinfo:
        validate_extension("report.pdf")
    assert ".pdf" in str(excinfo.value)
    with pytest.raises(UploadError):
        validate_extension("archive.zip")


# --- FR-5..8: log parsing ------------------------------------------------------

def _parse(name, ext):
    return parser.parse_file(os.path.join(SAMPLES, name), ext, name)


@pytest.mark.parametrize("name,ext", [
    ("auth_bruteforce.log", ".log"),
    ("web_access.log", ".log"),
])
def test_log_parse_success_rate_at_least_95(name, ext):
    """The SRS reliability target: print the actual measured rate."""
    df, meta = _parse(name, ext)
    rate = meta["parse_success_rate"]
    print(f"\n{name}: parse success rate = {rate:.1%} over {meta['row_count']} lines")
    assert rate >= 0.95


def test_syslog_fields_extracted():
    line = ("Aug 14 10:22:31 jumphost sshd[1234]: Failed password for root "
            "from 192.168.1.10 port 22 ssh2")
    fields = parser._parse_line(line)
    assert fields["src_ip"] == "192.168.1.10"
    assert fields["username"] == "root"
    assert "failed password" in fields["event"].lower()
    assert fields["timestamp"] == "Aug 14 10:22:31"


def test_apache_fields_extracted():
    line = ('192.168.1.5 - - [14/Aug/2026:10:22:31 +0000] "GET /login.php?id=1%27 HTTP/1.1" 200 512')
    fields = parser._parse_line(line)
    assert fields["src_ip"] == "192.168.1.5"
    assert fields["status"] == "200"
    assert fields["bytes"] == 512
    assert "GET /login.php?id=1%27" in fields["event"]


def test_iso_kv_fields_extracted():
    line = '2026-08-14 10:22:31,123 WARN user=admin ip=10.0.0.4 msg="bad thing"'
    fields = parser._parse_line(line)
    assert fields["src_ip"] == "10.0.0.4"
    assert fields["username"] == "admin"
    assert "bad thing" in fields["event"]


def test_generic_line_keeps_event():
    fields = parser._parse_line("weird service said something strange")
    assert fields["event"] == "weird service said something strange"


# --- FR-9/10: preprocessing ------------------------------------------------------

def test_timestamp_normalisation_mixed_formats():
    raw = pd.Series(["2026-08-14 10:22:31", "2026-08-14T10:22:31",
                     "Aug 14 10:22:31", "1755171751", "", None])
    decoded, unparsable = preprocess._decode_timestamps(raw)
    assert unparsable == 0
    assert decoded.notna().sum() == 4
    assert str(decoded.iloc[0]) == "2026-08-14 10:22:31"
    # No-year syslog dates get the current year, not 1900.
    assert decoded.iloc[2].year == pd.Timestamp.now().year
    assert decoded.iloc[2].year >= 2026


def test_duplicates_removed():
    df = pd.DataFrame({
        "row_id": [1, 2, 3],
        "timestamp": ["2026-01-01 00:00:00"] * 3,
        "src_ip": ["1.2.3.4"] * 3,
        "event": ["same thing"] * 3,
    })
    clean, summary = preprocess.preprocess(df.copy())
    assert summary["duplicates_removed"] == 2
    assert len(clean) == 1


def test_fuzzy_column_mapping():
    df = pd.DataFrame({
        "Source Address": ["10.0.0.1"],
        "Datetime": ["2026-08-14 10:22:31"],
        "Log Message": ["hello"],
        "Total Bytes": [512],
        "Attack Type": ["Normal"],
    })
    mapped, mapping = parser.map_columns(df)
    assert mapping["src_ip"] == "Source Address"
    assert mapping["timestamp"] == "Datetime"
    assert mapping["event"] == "Log Message"
    assert mapping["bytes"] == "Total Bytes"
    assert mapping["label_original"] == "Attack Type"
    assert "Source Address" not in mapped.columns


# --- FR-11..13: model, categories, severity ---------------------------------------

@pytest.fixture(scope="module")
def analysed_sample():
    df, meta = _parse("auth_bruteforce.log", ".log")
    clean, summary = preprocess.preprocess(df)
    predicted = analyzer.predict(clean)
    predicted = security.assign_severity(predicted)
    return predicted, stats.compute_stats(predicted, summary)


def test_model_loaded():
    assert analyzer.HAS_MODEL, "run python train_model.py before the tests"
    assert analyzer.metrics is not None
    assert analyzer.metrics["accuracy"] > 0.90


def test_prediction_shape(analysed_sample):
    predicted, _ = analysed_sample
    assert "predicted_category" in predicted.columns
    assert "confidence" in predicted.columns
    assert "is_anomaly" in predicted.columns
    assert predicted["confidence"].between(0, 1).all()
    known = {config.NORMAL_LABEL} | set(config.ATTACK_CATEGORIES)
    assert set(predicted["predicted_category"].unique()) <= known


def test_bruteforce_found_in_auth_sample(analysed_sample):
    predicted, results = analysed_sample
    assert results["total_attacks"] > 0
    assert "Brute Force" in results["category_counts"]
    # The bulk of the synthetic burst should be found, not a token few.
    assert results["category_counts"]["Brute Force"] >= 100


def test_severity_always_in_allowed_values(analysed_sample):
    predicted, results = analysed_sample
    assert set(results["severity_counts"].keys()) <= set(config.SEVERITY_LEVELS)
    anomalies = predicted[predicted["is_anomaly"]]
    assert set(anomalies["severity"].dropna().unique()) <= set(config.SEVERITY_LEVELS)


def test_stats_sanity(analysed_sample):
    _predicted, results = analysed_sample
    assert results["total_attacks"] + results["total_normal"] == results["total_records"]
    assert sum(results["category_counts"].values()) == results["total_attacks"]
    assert sum(results["severity_counts"].values()) == results["total_attacks"]
    assert 0 <= results["attack_pct"] <= 100


def test_clean_file_truthfully_empty():
    df, _meta = _parse("clean_normal.csv", ".csv")
    clean, summary = preprocess.preprocess(df)
    predicted = security.assign_severity(analyzer.predict(clean))
    results = stats.compute_stats(predicted, summary)
    assert results["total_attacks"] == 0
    assert results["category_counts"] == {}
    assert results["detections"] == []


def test_fuzzy_dataset_end_to_end():
    df, _meta = _parse("mixed_incidents.csv", ".csv")
    clean, summary = preprocess.preprocess(df)
    predicted = security.assign_severity(analyzer.predict(clean))
    results = stats.compute_stats(predicted, summary)
    assert results["total_attacks"] > 0
    assert set(results["category_counts"]) <= set(config.ATTACK_CATEGORIES)


# --- FR-16: PDF ---------------------------------------------------------------------

def test_pdf_generated_and_valid(analysed_sample, tmp_path):
    _predicted, results = analysed_sample
    out = tmp_path / "report.pdf"
    report.generate_report_pdf(
        results,
        {"filename": "auth_bruteforce.log",
         "summary_paragraphs": report.build_summary_paragraphs(results, "auth_bruteforce.log")},
        str(out),
    )
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 5_000
    assert b"/Page" in data


# --- uploads: guards and cleanup -------------------------------------------------------

def _upload_via_client(client, name, content, mimetype):
    data = {"file": (io.BytesIO(content), name, mimetype)}
    return client.post("/api/upload", data=data, content_type="multipart/form-data")


def test_macro_workbook_rejected(app_client):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("xl/vbaProject.bin", b"fake vba")
    response = _upload_via_client(app_client, "macro.xlsx", buffer.getvalue(),
                                  "application/vnd.ms-excel")
    assert response.status_code == 400
    assert "macro" in response.get_json()["error"].lower()


def test_binary_file_rejected(app_client):
    response = _upload_via_client(app_client, "thing.csv", b"\x00\x01\x02binary", "text/csv")
    assert response.status_code == 400


def test_oversize_upload_rejected(app_client):
    response = _upload_via_client(app_client, "big.log", b"x" * (config.MAX_UPLOAD_BYTES + 1),
                                  "text/plain")
    assert response.status_code in (400, 413)


def test_upload_preview_analyze_delete_roundtrip(app_client):
    with open(os.path.join(SAMPLES, "mixed_incidents.csv"), "rb") as fh:
        payload = fh.read()
    response = _upload_via_client(app_client, "mixed_incidents.csv", payload, "text/csv")
    assert response.status_code == 200
    analysis_id = response.get_json()["analysis_id"]

    preview = app_client.get(f"/api/preview/{analysis_id}").get_json()
    assert preview["row_count"] > 500
    assert any("Attack Type" in w or "mapped" in w for w in preview["warnings"]) or preview["warnings"]

    start = app_client.post(f"/api/analyze/{analysis_id}")
    assert start.status_code == 200
    # Wait for the background thread.
    import time
    for _ in range(120):
        state = app_client.get(f"/api/progress/{analysis_id}").get_json()
        if state["status"] in ("done", "failed"):
            break
        time.sleep(0.25)
    assert state["status"] == "done", state.get("error")

    results = app_client.get(f"/api/results/{analysis_id}").get_json()
    assert results["total_records"] > 500

    detections = app_client.get(f"/api/detections/{analysis_id}?page=1").get_json()
    assert detections["total"] == results["total_attacks"]

    pdf = app_client.get(f"/report/{analysis_id}/download")
    assert pdf.status_code == 200
    assert pdf.data[:5] == b"%PDF-"

    deleted = app_client.post(f"/api/delete/{analysis_id}")
    assert deleted.status_code == 200
    assert not os.path.isdir(os.path.join(config.TMP_DIR, analysis_id))
